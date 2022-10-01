use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound::*;
use std::sync::Arc;

use concread::bptree::{BptreeMap, BptreeMapReadTxn, BptreeMapWriteTxn};
use idlset::v2::IDLBitRange;
use kanidm_proto::v1::ConsistencyError;

use crate::prelude::*;
use crate::repl::cid::Cid;

pub struct ReplicationUpdateVector {
    // This sorts by time. Should we look up by IDL or by UUID?
    // I think IDL, because when we need to actually do the look ups we'll need
    // to send this list to the BE to get the affected entries.
    data: BptreeMap<Cid, IDLBitRange>,
}

impl Default for ReplicationUpdateVector {
    fn default() -> Self {
        let data: BptreeMap<Cid, IDLBitRange> = BptreeMap::new();
        ReplicationUpdateVector { data }
    }
}

impl ReplicationUpdateVector {
    pub fn write(&self) -> ReplicationUpdateVectorWriteTransaction<'_> {
        ReplicationUpdateVectorWriteTransaction {
            data: self.data.write(),
        }
    }

    pub fn read(&self) -> ReplicationUpdateVectorReadTransaction<'_> {
        ReplicationUpdateVectorReadTransaction {
            data: self.data.read(),
        }
    }
}

pub struct ReplicationUpdateVectorWriteTransaction<'a> {
    data: BptreeMapWriteTxn<'a, Cid, IDLBitRange>,
}

pub struct ReplicationUpdateVectorReadTransaction<'a> {
    data: BptreeMapReadTxn<'a, Cid, IDLBitRange>,
}

pub trait ReplicationUpdateVectorTransaction {
    fn ruv_snapshot(&self) -> BTreeMap<Cid, IDLBitRange>;

    fn verify(
        &self,
        entries: &[Arc<EntrySealedCommitted>],
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        // Okay rebuild the RUV in parallel.
        let mut check_ruv: BTreeMap<Cid, IDLBitRange> = BTreeMap::new();
        for entry in entries {
            // The DB id we need.
            let eid = entry.get_id();
            let eclog = entry.get_changelog();
            // We don't need the details of the change - only the cid of the
            // change that this entry was involved in.
            for cid in eclog.cid_iter() {
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
                    if cv == sv {
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
                    admin_warn!("{:?} is NOT consistent! CID missing from RUV", ck);
                    debug_assert!(false);
                    results.push(Err(ConsistencyError::RuvInconsistent(ck.to_string())));
                    check_next = check_iter.next();
                }
                Ordering::Greater => {
                    admin_warn!("{:?} is NOT consistent! CID should not exist in RUV", sk);
                    debug_assert!(false);
                    results.push(Err(ConsistencyError::RuvInconsistent(sk.to_string())));
                    snap_next = snap_iter.next();
                }
            }
        }

        while let Some((ck, _cv)) = &check_next {
            admin_warn!("{:?} is NOT consistent! CID missing from RUV", ck);
            debug_assert!(false);
            results.push(Err(ConsistencyError::RuvInconsistent(ck.to_string())));
            check_next = check_iter.next();
        }

        while let Some((sk, _sv)) = &snap_next {
            admin_warn!("{:?} is NOT consistent! CID should not exist in RUV", sk);
            debug_assert!(false);
            results.push(Err(ConsistencyError::RuvInconsistent(sk.to_string())));
            snap_next = snap_iter.next();
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
}

impl<'a> ReplicationUpdateVectorTransaction for ReplicationUpdateVectorReadTransaction<'a> {
    fn ruv_snapshot(&self) -> BTreeMap<Cid, IDLBitRange> {
        self.data
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl<'a> ReplicationUpdateVectorWriteTransaction<'a> {
    pub fn rebuild(&mut self, entries: &[Arc<EntrySealedCommitted>]) -> Result<(), OperationError> {
        // Entries and their internal changelogs are the "source of truth" for all changes
        // that have ever occured and are stored on this server. So we use them to rebuild our RUV
        // here!
        let mut rebuild_ruv: BTreeMap<Cid, IDLBitRange> = BTreeMap::new();

        for entry in entries {
            // The DB id we need.
            let eid = entry.get_id();
            let eclog = entry.get_changelog();
            // We don't need the details of the change - only the cid of the
            // change that this entry was involved in.
            for cid in eclog.cid_iter() {
                if let Some(idl) = rebuild_ruv.get_mut(cid) {
                    // We can't guarantee id order, so we have to do this properly.
                    idl.insert_id(eid);
                } else {
                    let mut idl = IDLBitRange::new();
                    idl.insert_id(eid);
                    rebuild_ruv.insert(cid.clone(), idl);
                }
            }
        }

        // Finally, we need to do a cleanup/compact of the IDL's if possible.
        rebuild_ruv.iter_mut().for_each(|(_k, idl)| {
            idl.maybe_compress();
        });

        self.data.clear();
        self.data.extend(rebuild_ruv.into_iter());

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

        self.data
            .range((Unbounded, Excluded(cid)))
            .for_each(|(_, ex_idl)| {
                idl = ex_idl as &_ | &idl;
            });

        // Trim all cid's up to this value, and return the range of IDs
        // that are affected.
        self.data.split_off_lt(cid);

        Ok(idl)
    }

    pub fn commit(self) {
        self.data.commit();
    }
}
