use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::*;
use std::sync::Arc;
use std::time::Duration;

use concread::bptree::{BptreeMap, BptreeMapReadTxn, BptreeMapWriteTxn};
use idlset::v2::IDLBitRange;
use kanidm_proto::v1::ConsistencyError;

use crate::prelude::*;
use crate::repl::cid::Cid;
use std::fmt;

pub struct ReplicationUpdateVector {
    // This sorts by time. We store the set of entry id's that are affected in an operation.
    // Due to how replication state works, it is possibly that id's in these sets *may* not
    // exist anymore, so these bit ranges likely need intersection with allids before use.
    data: BptreeMap<Cid, IDLBitRange>,
    // This sorts by Server ID. It's used for the RUV to build ranges for you ... guessed it
    // range queries. These are used to build the set of differences that need to be sent in
    // a replication operation.
    //
    // we need a way to invert the cid, but without duplication? Maybe an invert cid type?
    // This way it still orders things in the right order by time stamp just searches by cid
    // first.
    ranged: BptreeMap<Uuid, BTreeSet<Duration>>,
}

impl Default for ReplicationUpdateVector {
    fn default() -> Self {
        ReplicationUpdateVector {
            data: BptreeMap::default(),
            ranged: BptreeMap::default(),
        }
    }
}

impl ReplicationUpdateVector {
    pub fn write(&self) -> ReplicationUpdateVectorWriteTransaction<'_> {
        ReplicationUpdateVectorWriteTransaction {
            data: self.data.write(),
            ranged: self.ranged.write(),
        }
    }

    pub fn read(&self) -> ReplicationUpdateVectorReadTransaction<'_> {
        ReplicationUpdateVectorReadTransaction {
            data: self.data.read(),
            ranged: self.ranged.read(),
        }
    }
}

pub struct ReplicationUpdateVectorWriteTransaction<'a> {
    data: BptreeMapWriteTxn<'a, Cid, IDLBitRange>,
    ranged: BptreeMapWriteTxn<'a, Uuid, BTreeSet<Duration>>,
}

impl<'a> fmt::Debug for ReplicationUpdateVectorWriteTransaction<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "RUV DUMP")?;
        self.data
            .iter()
            .try_for_each(|(cid, idl)| writeln!(f, "* [{cid} {idl:?}]"))
    }
}

pub struct ReplicationUpdateVectorReadTransaction<'a> {
    data: BptreeMapReadTxn<'a, Cid, IDLBitRange>,
    ranged: BptreeMapReadTxn<'a, Uuid, BTreeSet<Duration>>,
}

pub trait ReplicationUpdateVectorTransaction {
    fn ruv_snapshot(&self) -> BTreeMap<Cid, IDLBitRange>;

    fn range_snapshot(&self) -> BTreeMap<Uuid, &BTreeSet<Duration>>;

    fn verify(
        &self,
        entries: &[Arc<EntrySealedCommitted>],
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        // Okay rebuild the RUV in parallel.
        let mut check_ruv: BTreeMap<Cid, IDLBitRange> = BTreeMap::default();
        for entry in entries {
            // The DB id we need.
            let eid = entry.get_id();
            let ecstate = entry.get_changestate();
            // We don't need the details of the change - only the cid of the
            // change that this entry was involved in.
            for cid in ecstate.cid_iter() {
                // Add to the main ruv data.
                if let Some(idl) = check_ruv.get_mut(cid) {
                    // We can't guarantee id order, so we have to do this properly.
                    idl.insert_id(eid);
                } else {
                    let mut idl = IDLBitRange::new();
                    idl.insert_id(eid);
                    check_ruv.insert(cid.clone(), idl);
                }
            }
        }

        trace!(?check_ruv);
        // Get the current state
        let snapshot_ruv = self.ruv_snapshot();
        trace!(?snapshot_ruv);

        // Now compare. We want to do this checking for each CID in each, and then asserting
        // the content is the same.

        let mut check_iter = check_ruv.iter();
        let mut snap_iter = snapshot_ruv.iter();

        let mut check_next = check_iter.next();
        let mut snap_next = snap_iter.next();

        while let (Some((ck, cv)), Some((sk, sv))) = (&check_next, &snap_next) {
            match ck.cmp(sk) {
                Ordering::Equal => {
                    // Counter intuitive, but here we check that the check set is a *subset*
                    // of the ruv snapshot. This is because when we have an entry that is
                    // tombstoned, all it's CID interactions are "lost" and it's cid becomes
                    // that of when it was tombstoned. So the "rebuilt" ruv will miss that
                    // entry.
                    //
                    // In the future the RUV concept may be ditched entirely anyway, thoughts needed.
                    let intersect = *cv & *sv;
                    if *cv == &intersect {
                        trace!("{:?} is consistent!", ck);
                    } else {
                        admin_warn!("{:?} is NOT consistent! IDL's differ", ck);
                        debug_assert!(false);
                        results.push(Err(ConsistencyError::RuvInconsistent(ck.to_string())));
                    }
                    check_next = check_iter.next();
                    snap_next = snap_iter.next();
                }
                Ordering::Less => {
                    // Due to deletes, it can be that the check ruv is missing whole entries
                    // in a rebuild.
                    admin_warn!("{:?} is NOT consistent! CID missing from RUV", ck);
                    // debug_assert!(false);
                    // results.push(Err(ConsistencyError::RuvInconsistent(ck.to_string())));
                    check_next = check_iter.next();
                }
                Ordering::Greater => {
                    admin_warn!("{:?} is NOT consistent! CID should not exist in RUV", sk);
                    // debug_assert!(false);
                    // results.push(Err(ConsistencyError::RuvInconsistent(sk.to_string())));
                    snap_next = snap_iter.next();
                }
            }
        }

        while let Some((ck, _cv)) = &check_next {
            admin_warn!("{:?} is NOT consistent! CID missing from RUV", ck);
            // debug_assert!(false);
            // results.push(Err(ConsistencyError::RuvInconsistent(ck.to_string())));
            check_next = check_iter.next();
        }

        while let Some((sk, _sv)) = &snap_next {
            admin_warn!("{:?} is NOT consistent! CID should not exist in RUV", sk);
            // debug_assert!(false);
            // results.push(Err(ConsistencyError::RuvInconsistent(sk.to_string())));
            snap_next = snap_iter.next();
        }

        // Assert that the content of the ranged set matches the data set and has the
        // correct set of values.
        let snapshot_range = self.range_snapshot();

        for cid in snapshot_ruv.keys() {
            if let Some(server_range) = snapshot_range.get(&cid.s_uuid) {
                if !server_range.contains(&cid.ts) {
                    admin_warn!(
                        "{:?} is NOT consistent! server range is missing cid in index",
                        cid
                    );
                    debug_assert!(false);
                    results.push(Err(ConsistencyError::RuvInconsistent(
                        cid.s_uuid.to_string(),
                    )));
                }
            } else {
                admin_warn!(
                    "{:?} is NOT consistent! server range is not present",
                    cid.s_uuid
                );
                debug_assert!(false);
                results.push(Err(ConsistencyError::RuvInconsistent(
                    cid.s_uuid.to_string(),
                )));
            }
        }

        // Done!
    }
}

impl<'a> ReplicationUpdateVectorTransaction for ReplicationUpdateVectorWriteTransaction<'a> {
    fn ruv_snapshot(&self) -> BTreeMap<Cid, IDLBitRange> {
        self.data
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn range_snapshot(&self) -> BTreeMap<Uuid, &BTreeSet<Duration>> {
        self.ranged.iter().map(|(k, v)| (*k, v)).collect()
    }
}

impl<'a> ReplicationUpdateVectorTransaction for ReplicationUpdateVectorReadTransaction<'a> {
    fn ruv_snapshot(&self) -> BTreeMap<Cid, IDLBitRange> {
        self.data
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn range_snapshot(&self) -> BTreeMap<Uuid, &BTreeSet<Duration>> {
        self.ranged.iter().map(|(k, v)| (*k, v)).collect()
    }
}

impl<'a> ReplicationUpdateVectorWriteTransaction<'a> {
    pub fn clear(&mut self) {
        self.data.clear();
        self.ranged.clear();
    }

    pub fn rebuild(&mut self, entries: &[Arc<EntrySealedCommitted>]) -> Result<(), OperationError> {
        // Drop everything.
        self.clear();
        // Entries and their internal changelogs are the "source of truth" for all changes
        // that have ever occurred and are stored on this server. So we use them to rebuild our RUV
        // here!
        let mut rebuild_ruv: BTreeMap<Cid, IDLBitRange> = BTreeMap::new();
        let mut rebuild_range: BTreeMap<Uuid, BTreeSet<Duration>> = BTreeMap::default();

        for entry in entries {
            // The DB id we need.
            let eid = entry.get_id();
            let ecstate = entry.get_changestate();
            // We don't need the details of the change - only the cid of the
            // change that this entry was involved in.
            for cid in ecstate.cid_iter() {
                if let Some(idl) = rebuild_ruv.get_mut(cid) {
                    // We can't guarantee id order, so we have to do this properly.
                    idl.insert_id(eid);
                } else {
                    let mut idl = IDLBitRange::new();
                    idl.insert_id(eid);
                    rebuild_ruv.insert(cid.clone(), idl);
                }

                if let Some(server_range) = rebuild_range.get_mut(&cid.s_uuid) {
                    server_range.insert(cid.ts);
                } else {
                    let mut ts_range = BTreeSet::default();
                    ts_range.insert(cid.ts);
                    rebuild_range.insert(cid.s_uuid, ts_range);
                }
            }
        }

        // Finally, we need to do a cleanup/compact of the IDL's if possible.
        rebuild_ruv.iter_mut().for_each(|(_k, idl)| {
            idl.maybe_compress();
        });

        self.data.extend(rebuild_ruv.into_iter());
        self.ranged.extend(rebuild_range.into_iter());

        Ok(())
    }

    pub fn insert_change(&mut self, cid: &Cid, idl: IDLBitRange) -> Result<(), OperationError> {
        // Remember, in a transaction the changes can be updated multiple times.
        if let Some(ex_idl) = self.data.get_mut(cid) {
            // This ensures both sets have all the available ids.
            let idl = ex_idl as &_ | &idl;
            *ex_idl = idl;
        } else {
            self.data.insert(cid.clone(), idl);
        }

        if let Some(server_range) = self.ranged.get_mut(&cid.s_uuid) {
            server_range.insert(cid.ts);
        } else {
            let mut range = BTreeSet::default();
            range.insert(cid.ts);
            self.ranged.insert(cid.s_uuid, range);
        }

        Ok(())
    }

    pub fn ruv_idls(&self) -> IDLBitRange {
        let mut idl = IDLBitRange::new();
        self.data.iter().for_each(|(_cid, ex_idl)| {
            idl = ex_idl as &_ | &idl;
        });
        idl
    }

    /*
    pub fn contains(&self, idl: &IDLBitRange) -> bool {
        self.data.iter()
            .any(|(cid, ex_idl)| {
                let idl_result = idl & ex_idl;
                if idl_result.is_empty() {
                    false
                } else {
                    debug!(?cid, ?idl_result);
                    true
                }
            })
    }
    */

    pub fn trim_up_to(&mut self, cid: &Cid) -> Result<IDLBitRange, OperationError> {
        let mut idl = IDLBitRange::new();
        let mut remove_suuid = Vec::default();

        // Here we can use the for_each here to be trimming the
        // range set since that is not ordered by time, we need
        // to do fragmented searches over this no matter what we
        // try to do.

        for (cid, ex_idl) in self.data.range((Unbounded, Excluded(cid))) {
            idl = ex_idl as &_ | &idl;

            // Remove the reverse version of the cid from the ranged index.
            match self.ranged.get_mut(&cid.s_uuid) {
                Some(server_range) => {
                    // Remove returns a bool if the element WAS present.
                    if !server_range.remove(&cid.ts) {
                        error!("Impossible State - The RUV is corrupted due to missing sid:ts pair in ranged index");
                        return Err(OperationError::InvalidState);
                    }
                    if server_range.is_empty() {
                        remove_suuid.push(cid.s_uuid);
                    }
                }
                None => {
                    error!("Impossible State - The RUV is corrupted due to missing sid in ranged index");
                    return Err(OperationError::InvalidState);
                }
            }
        }

        for s_uuid in remove_suuid {
            let x = self.ranged.remove(&s_uuid);
            assert!(x.map(|y| y.is_empty()).unwrap_or(false))
        }

        // Trim all cid's up to this value, and return the range of IDs
        // that are affected.
        self.data.split_off_lt(cid);

        Ok(idl)
    }

    pub fn commit(self) {
        self.data.commit();
        self.ranged.commit();
    }
}
