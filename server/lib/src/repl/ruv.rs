use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::*;
use std::sync::Arc;
use std::time::Duration;

use concread::bptree::{BptreeMap, BptreeMapReadSnapshot, BptreeMapReadTxn, BptreeMapWriteTxn};
use idlset::v2::IDLBitRange;
use kanidm_proto::v1::ConsistencyError;

use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::repl::proto::ReplCidRange;
use std::fmt;

#[derive(Default)]
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

/// The status of replication after investigating the RUV states.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RangeDiffStatus {
    /// Ok - can proceed with replication, supplying the following
    /// ranges of changes to the consumer.
    Ok(BTreeMap<Uuid, ReplCidRange>),
    /// Refresh - The consumer is lagging and is missing a set of changes
    /// that are required to proceed. The consumer *MUST* be refreshed
    /// immediately.
    Refresh {
        lag_range: BTreeMap<Uuid, ReplCidRange>,
    },
    /// Unwilling - The consumer is advanced beyond our state, and supplying
    /// changes to them may introduce inconsistency in replication. This
    /// server should be investigated immediately.
    Unwilling {
        adv_range: BTreeMap<Uuid, ReplCidRange>,
    },
    /// Critical - The consumer is lagging and missing changes, but also is
    /// in possesion of changes advancing it beyond our current state. This
    /// is a critical fault in replication and the topology must be
    /// investigated immediately.
    Critical {
        lag_range: BTreeMap<Uuid, ReplCidRange>,
        adv_range: BTreeMap<Uuid, ReplCidRange>,
    },
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

    pub(crate) fn range_diff(
        consumer_range: &BTreeMap<Uuid, ReplCidRange>,
        supplier_range: &BTreeMap<Uuid, ReplCidRange>,
    ) -> RangeDiffStatus {
        // We need to build a new set of ranges that express the difference between
        // these two states.
        let mut diff_range = BTreeMap::default();
        let mut lag_range = BTreeMap::default();
        let mut adv_range = BTreeMap::default();

        let mut consumer_lagging = false;
        let mut supplier_lagging = false;

        // We need to look at each uuid in the *supplier* and assert if they are present
        // on the *consumer*.
        //
        // If there are s_uuids with the same max, we don't add it to the
        // diff

        for (supplier_s_uuid, supplier_cid_range) in supplier_range.iter() {
            match consumer_range.get(supplier_s_uuid) {
                Some(consumer_cid_range) => {
                    // The two windows just have to overlap. If they over lap
                    // meaning that consumer max > supplier min, then if supplier
                    // max > consumer max, then the range between consumer max
                    // and supplier max must be supplied.
                    //
                    //   consumer min     consumer max
                    //      <--   supplier min             supplier max -->
                    //
                    // In other words if we have:
                    //
                    //   consumer min  consumer max
                    //                                supplier min  supplier max
                    //
                    // then because there has been too much lag between consumer and
                    // the supplier then there is a risk of changes being dropped or
                    // missing. In the future we could alter this to force the resend
                    // of zero -> supplier max, but I think thought is needed to
                    // ensure no corruption in this case.
                    if consumer_cid_range.ts_max < supplier_cid_range.ts_min {
                        consumer_lagging = true;
                        lag_range.insert(
                            *supplier_s_uuid,
                            ReplCidRange {
                                ts_min: supplier_cid_range.ts_min,
                                ts_max: consumer_cid_range.ts_max,
                            },
                        );
                    } else if supplier_cid_range.ts_max < consumer_cid_range.ts_min {
                        // It could be valid in this case to ignore this instead
                        // of erroring as changelog trim has occured? Thought needed.
                        supplier_lagging = true;
                        adv_range.insert(
                            *supplier_s_uuid,
                            ReplCidRange {
                                ts_min: supplier_cid_range.ts_max,
                                ts_max: consumer_cid_range.ts_min,
                            },
                        );
                    } else if consumer_cid_range.ts_max < supplier_cid_range.ts_max {
                        // We require the changes from consumer max -> supplier max.
                        diff_range.insert(
                            *supplier_s_uuid,
                            ReplCidRange {
                                ts_min: consumer_cid_range.ts_max,
                                ts_max: supplier_cid_range.ts_max,
                            },
                        );
                    }
                    // else ...
                    // In this case there is no action required since consumer_cid_range.ts_max
                    // must be greater than or equal to supplier max.
                }
                None => {
                    // The consumer does not have any content from this
                    // server. Select from Zero -> max of the supplier.
                    diff_range.insert(
                        *supplier_s_uuid,
                        ReplCidRange {
                            ts_min: Duration::ZERO,
                            ts_max: supplier_cid_range.ts_max,
                        },
                    );
                }
            }
        }

        match (consumer_lagging, supplier_lagging) {
            (false, false) => RangeDiffStatus::Ok(diff_range),
            (true, false) => RangeDiffStatus::Refresh { lag_range },
            (false, true) => RangeDiffStatus::Unwilling { adv_range },
            (true, true) => RangeDiffStatus::Critical {
                lag_range,
                adv_range,
            },
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
    fn ruv_snapshot(&self) -> BptreeMapReadSnapshot<'_, Cid, IDLBitRange>;

    fn range_snapshot(&self) -> BptreeMapReadSnapshot<'_, Uuid, BTreeSet<Duration>>;

    fn current_ruv_range(&self) -> Result<BTreeMap<Uuid, ReplCidRange>, OperationError> {
        self.range_snapshot()
            .iter()
            .map(|(s_uuid, range)| match (range.first(), range.last()) {
                (Some(first), Some(last)) => Ok((
                    *s_uuid,
                    ReplCidRange {
                        ts_min: *first,
                        ts_max: *last,
                    },
                )),
                _ => {
                    error!(
                        "invalid state for server uuid {:?}, no ranges present",
                        s_uuid
                    );
                    Err(OperationError::InvalidState)
                }
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
    }

    fn range_to_idl(&self, ctx_ranges: &BTreeMap<Uuid, ReplCidRange>) -> IDLBitRange {
        let mut idl = IDLBitRange::new();
        // Force the set to be compressed, saves on seeks during
        // inserts.
        idl.compress();
        let range = self.range_snapshot();
        let ruv = self.ruv_snapshot();

        // The range we have has a collection of s_uuid containing low -> high ranges.
        // We need to convert this to absolute ranges of all the idlbitranges that
        // relate to the entries we have.

        for (s_uuid, ctx_range) in ctx_ranges {
            // For each server and range low to high, iterate over
            // the list of CID's in the main RUV.

            let ruv_range = match range.get(s_uuid) {
                Some(r) => r,
                None => {
                    // This is valid because if we clean up a server range on
                    // this node, but the other server isn't aware yet, so we
                    // just no-op this. The changes we have will still be
                    // correctly found and sent.
                    debug!(?s_uuid, "range not found in ruv.");
                    continue;
                }
            };

            // Get from the min to the max. Unbounded and
            // Included(ctx_range.ts_max) are the same in
            // this context.

            for ts in ruv_range.range((Excluded(ctx_range.ts_min), Unbounded)) {
                let cid = Cid {
                    ts: *ts,
                    s_uuid: *s_uuid,
                };

                if let Some(ruv_idl) = ruv.get(&cid) {
                    ruv_idl.into_iter().for_each(|id| idl.insert_id(id))
                }
                // If the cid isn't found, it may have been trimmed, but thats okay.
            }
        }

        idl
    }

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
    fn ruv_snapshot(&self) -> BptreeMapReadSnapshot<'_, Cid, IDLBitRange> {
        self.data.to_snapshot()
    }

    fn range_snapshot(&self) -> BptreeMapReadSnapshot<'_, Uuid, BTreeSet<Duration>> {
        self.ranged.to_snapshot()
    }
}

impl<'a> ReplicationUpdateVectorTransaction for ReplicationUpdateVectorReadTransaction<'a> {
    fn ruv_snapshot(&self) -> BptreeMapReadSnapshot<'_, Cid, IDLBitRange> {
        self.data.to_snapshot()
    }

    fn range_snapshot(&self) -> BptreeMapReadSnapshot<'_, Uuid, BTreeSet<Duration>> {
        self.ranged.to_snapshot()
    }
}

impl<'a> ReplicationUpdateVectorWriteTransaction<'a> {
    pub fn clear(&mut self) {
        self.data.clear();
        self.ranged.clear();
    }

    pub(crate) fn refresh_validate_ruv(
        &self,
        ctx_ranges: &BTreeMap<Uuid, ReplCidRange>,
    ) -> Result<(), OperationError> {
        // Assert that the ruv that currently exists, is a valid data set of
        // the supplied consumer range - especially check that when a uuid exists in
        // our ruv, that it's maximum matches the ctx ruv.
        //
        // Since the ctx range comes from the supplier, when we rebuild due to the
        // state machine then some values may not exist since they were replaced. But
        // the server uuid maximums must exist.
        let mut valid = true;
        for (server_uuid, server_range) in self.ranged.iter() {
            match ctx_ranges.get(server_uuid) {
                Some(ctx_range) => {
                    let ctx_ts = &ctx_range.ts_max;
                    match server_range.last() {
                        Some(s_ts) if ctx_ts == s_ts => {
                            // Ok
                            trace!(?server_uuid, ?ctx_ts, ?s_ts, "valid");
                        }
                        Some(s_ts) => {
                            valid = false;
                            warn!(?server_uuid, ?ctx_ts, ?s_ts, "inconsistent s_uuid in ruv");
                        }
                        None => {
                            valid = false;
                            warn!(?server_uuid, ?ctx_ts, "inconsistent server range in ruv");
                        }
                    }
                }
                None => {
                    valid = false;
                    error!(?server_uuid, "s_uuid absent from in ruv");
                }
            }
        }

        if valid {
            Ok(())
        } else {
            Err(OperationError::ReplInvalidRUVState)
        }
    }

    pub(crate) fn refresh_update_ruv(
        &mut self,
        ctx_ranges: &BTreeMap<Uuid, ReplCidRange>,
    ) -> Result<(), OperationError> {
        for (ctx_s_uuid, ctx_range) in ctx_ranges.iter() {
            if let Some(s_range) = self.ranged.get_mut(ctx_s_uuid) {
                // Just assert the max is what we have.
                s_range.insert(ctx_range.ts_max);
            } else {
                let s_range = btreeset!(ctx_range.ts_max);
                self.ranged.insert(*ctx_s_uuid, s_range);
            }
        }
        Ok(())
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

    pub fn update_entry_changestate(
        &mut self,
        entry: &EntrySealedCommitted,
    ) -> Result<(), OperationError> {
        let eid = entry.get_id();
        let ecstate = entry.get_changestate();

        for cid in ecstate.cid_iter() {
            if let Some(idl) = self.data.get_mut(cid) {
                // We can't guarantee id order, so we have to do this properly.
                idl.insert_id(eid);
            } else {
                let mut idl = IDLBitRange::new();
                idl.insert_id(eid);
                self.data.insert(cid.clone(), idl);
            }

            if let Some(server_range) = self.ranged.get_mut(&cid.s_uuid) {
                server_range.insert(cid.ts);
            } else {
                let mut ts_range = BTreeSet::default();
                ts_range.insert(cid.ts);
                self.ranged.insert(cid.s_uuid, ts_range);
            }
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

    /*
        How to handle changelog trimming? If we trim a server out from the RUV as a whole, we
        need to be sure we don't oversupply changes the consumer already has. How can we do
        this cleanly? Or do we just deal with it because our own local trim will occur soon after?

        The situation would be

        A:   1    ->    3
        B:   1    ->    3

        Assuming A trims first:

        A:
        B:   1    ->    3

        Then on A <- B, B would try to supply 1->3 to A assuming it is not present. However,
        the trim would occur soon after on B causing:

        A:
        B:

        And then the supply would stop. So either A needs to retain the max/min in it's range
        to allow the comparison here to continue even if it's ruv is cleaned. Or, we need to
        have a delayed trim on the range that is 2x the normal trim range to give a buffer?

        Mostly longer ruv/cid ranges aren't an issue for us, so could we just maek these ranges
        really large?
    */

    // Problem Cases

    /*
       What about generations? There is a "live" generation which can be replicated and a
       former generation of ranges that previously existed. To replicate:
           // The consumer must have content within the current live range.
           consumer.live_max < supplier.live_max
           consumer.live_max >= supplier.live_min
           // The consumer must have all content that was formerly known.
           consumer.live_min >= supplier.former_max
           // I don't think we care what
    */

    /*

      B and C must be sequential to an s_uuid.

      Former (trimmed) | Live (current)
      A <-> B          | C <-> D

      0 <-> A          | B <-> B

    */

    pub fn trim_up_to(&mut self, cid: &Cid) -> Result<IDLBitRange, OperationError> {
        let mut idl = IDLBitRange::new();
        // let mut remove_suuid = Vec::default();

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
                    let last = match server_range.last() {
                        Some(l) => *l,
                        None => {
                            error!("Impossible State - The RUV should not be empty");
                            return Err(OperationError::InvalidState);
                        }
                    };

                    if cid.ts != last {
                        if !server_range.remove(&cid.ts) {
                            error!("Impossible State - The RUV is corrupted due to missing sid:ts pair in ranged index");
                            return Err(OperationError::InvalidState);
                        }
                    } else {
                        trace!("skipping maximum cid for s_uuid");
                    }
                    if server_range.is_empty() {
                        // remove_suuid.push(cid.s_uuid);
                        error!("Impossible State - The RUV should not be cleared for a s_uuid!");
                        return Err(OperationError::InvalidState);
                    }
                }
                None => {
                    error!("Impossible State - The RUV is corrupted due to missing sid in ranged index");
                    return Err(OperationError::InvalidState);
                }
            }
        }

        /*
        for s_uuid in remove_suuid {
            let x = self.ranged.remove(&s_uuid);
            assert!(x.map(|y| y.is_empty()).unwrap_or(false))
        }
        */

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

#[cfg(test)]
mod tests {
    use super::RangeDiffStatus;
    use super::ReplCidRange;
    use super::ReplicationUpdateVector;
    use std::collections::BTreeMap;
    use std::time::Duration;

    const UUID_A: uuid::Uuid = uuid::uuid!("13b530b0-efdd-4934-8fb7-9c35c8aab79e");
    const UUID_B: uuid::Uuid = uuid::uuid!("16327cf8-6a34-4a17-982c-b2eaa6d02d00");
    const UUID_C: uuid::Uuid = uuid::uuid!("2ed717e3-15be-41e6-b966-10a1f6d7ea1c");

    #[test]
    fn test_ruv_range_diff_1() {
        let ctx_a = BTreeMap::default();
        let ctx_b = BTreeMap::default();

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Ok(BTreeMap::default());
        assert_eq!(result, expect);

        // Test the inverse.
        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Ok(BTreeMap::default());
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_2() {
        let ctx_a = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(3),
            }
        ));
        let ctx_b = BTreeMap::default();

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Ok(BTreeMap::default());
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Ok(btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::ZERO,
                ts_max: Duration::from_secs(3),
            }
        )));
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_3() {
        let ctx_a = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(3),
            }
        ));
        let ctx_b = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(3),
            }
        ));

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Ok(BTreeMap::default());
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Ok(BTreeMap::default());
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_4() {
        let ctx_a = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(3),
            }
        ));
        let ctx_b = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(4),
            }
        ));

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Ok(btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(3),
                ts_max: Duration::from_secs(4),
            }
        )));
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Ok(BTreeMap::default());
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_5() {
        let ctx_a = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(5),
                ts_max: Duration::from_secs(7),
            }
        ));
        let ctx_b = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(4),
            }
        ));

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Unwilling {
            adv_range: btreemap!((
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(4),
                    ts_max: Duration::from_secs(5),
                }
            )),
        };
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Refresh {
            lag_range: btreemap!((
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(5),
                    ts_max: Duration::from_secs(4),
                }
            )),
        };
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_6() {
        let ctx_a = btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(1),
                ts_max: Duration::from_secs(4),
            }
        ));
        let ctx_b = btreemap!(
            (
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(1),
                    ts_max: Duration::from_secs(3),
                }
            ),
            (
                UUID_B,
                ReplCidRange {
                    ts_min: Duration::from_secs(2),
                    ts_max: Duration::from_secs(4),
                }
            )
        );

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Ok(btreemap!((
            UUID_B,
            ReplCidRange {
                ts_min: Duration::ZERO,
                ts_max: Duration::from_secs(4),
            }
        )));
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Ok(btreemap!((
            UUID_A,
            ReplCidRange {
                ts_min: Duration::from_secs(3),
                ts_max: Duration::from_secs(4),
            }
        )));
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_7() {
        let ctx_a = btreemap!(
            (
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(1),
                    ts_max: Duration::from_secs(4),
                }
            ),
            (
                UUID_C,
                ReplCidRange {
                    ts_min: Duration::from_secs(2),
                    ts_max: Duration::from_secs(5),
                }
            )
        );
        let ctx_b = btreemap!(
            (
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(1),
                    ts_max: Duration::from_secs(3),
                }
            ),
            (
                UUID_B,
                ReplCidRange {
                    ts_min: Duration::from_secs(2),
                    ts_max: Duration::from_secs(4),
                }
            ),
            (
                UUID_C,
                ReplCidRange {
                    ts_min: Duration::from_secs(3),
                    ts_max: Duration::from_secs(4),
                }
            )
        );

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Ok(btreemap!((
            UUID_B,
            ReplCidRange {
                ts_min: Duration::ZERO,
                ts_max: Duration::from_secs(4),
            }
        )));
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Ok(btreemap!(
            (
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(3),
                    ts_max: Duration::from_secs(4),
                }
            ),
            (
                UUID_C,
                ReplCidRange {
                    ts_min: Duration::from_secs(4),
                    ts_max: Duration::from_secs(5),
                }
            )
        ));
        assert_eq!(result, expect);
    }

    #[test]
    fn test_ruv_range_diff_8() {
        let ctx_a = btreemap!(
            (
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(4),
                    ts_max: Duration::from_secs(6),
                }
            ),
            (
                UUID_B,
                ReplCidRange {
                    ts_min: Duration::from_secs(1),
                    ts_max: Duration::from_secs(2),
                }
            )
        );
        let ctx_b = btreemap!(
            (
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(1),
                    ts_max: Duration::from_secs(2),
                }
            ),
            (
                UUID_B,
                ReplCidRange {
                    ts_min: Duration::from_secs(4),
                    ts_max: Duration::from_secs(6),
                }
            )
        );

        let result = ReplicationUpdateVector::range_diff(&ctx_a, &ctx_b);
        let expect = RangeDiffStatus::Critical {
            adv_range: btreemap!((
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(2),
                    ts_max: Duration::from_secs(4),
                }
            )),
            lag_range: btreemap!((
                UUID_B,
                ReplCidRange {
                    ts_min: Duration::from_secs(4),
                    ts_max: Duration::from_secs(2),
                }
            )),
        };
        assert_eq!(result, expect);

        let result = ReplicationUpdateVector::range_diff(&ctx_b, &ctx_a);
        let expect = RangeDiffStatus::Critical {
            adv_range: btreemap!((
                UUID_B,
                ReplCidRange {
                    ts_min: Duration::from_secs(2),
                    ts_max: Duration::from_secs(4),
                }
            )),
            lag_range: btreemap!((
                UUID_A,
                ReplCidRange {
                    ts_min: Duration::from_secs(4),
                    ts_max: Duration::from_secs(2),
                }
            )),
        };
        assert_eq!(result, expect);
    }
}
