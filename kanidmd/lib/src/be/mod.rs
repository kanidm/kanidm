//! The backend. This contains the "low level" storage and query code, which is
//! implemented as a json-like kv document database. This has no rules about content
//! of the server, which are all enforced at higher levels. The role of the backend
//! is to persist content safely to disk, load that content, and execute queries
//! utilising indexes in the most effective way possible.

use std::fs;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;

use concread::cowcell::*;
use hashbrown::{HashMap as Map, HashSet};
use idlset::v2::IDLBitRange;
use idlset::AndNot;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use smartstring::alias::String as AttrString;
use tracing::{trace, trace_span};
use uuid::Uuid;

use crate::be::dbentry::{DbBackup, DbEntry};
use crate::entry::{Entry, EntryCommitted, EntryNew, EntrySealed};
use crate::filter::{Filter, FilterPlan, FilterResolved, FilterValidResolved};
use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::repl::ruv::{
    ReplicationUpdateVector, ReplicationUpdateVectorReadTransaction,
    ReplicationUpdateVectorTransaction, ReplicationUpdateVectorWriteTransaction,
};
use crate::value::{IndexType, Value};

pub mod dbentry;
pub mod dbvalue;
mod idl_arc_sqlite;
mod idl_sqlite;
pub(crate) mod idxkey;

pub(crate) use self::idxkey::{IdxKey, IdxKeyRef, IdxKeyToRef, IdxSlope};
use crate::be::idl_arc_sqlite::{
    IdlArcSqlite, IdlArcSqliteReadTransaction, IdlArcSqliteTransaction,
    IdlArcSqliteWriteTransaction,
};
// Re-export this
pub use crate::be::idl_sqlite::FsType;

// Currently disabled due to improvements in idlset for intersection handling.
const FILTER_SEARCH_TEST_THRESHOLD: usize = 0;
const FILTER_EXISTS_TEST_THRESHOLD: usize = 0;

#[derive(Debug, Clone)]
/// Limits on the resources a single event can consume. These are defined per-event
/// as they are derived from the userAuthToken based on that individual session
pub struct Limits {
    pub unindexed_allow: bool,
    pub search_max_results: usize,
    pub search_max_filter_test: usize,
    pub filter_max_elements: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            unindexed_allow: false,
            search_max_results: 256,
            search_max_filter_test: 512,
            filter_max_elements: 32,
        }
    }
}

impl Limits {
    pub fn unlimited() -> Self {
        Limits {
            unindexed_allow: true,
            search_max_results: usize::MAX,
            search_max_filter_test: usize::MAX,
            filter_max_elements: usize::MAX,
        }
    }
}

#[derive(Debug, Clone)]
pub enum IdList {
    AllIds,
    PartialThreshold(IDLBitRange),
    Partial(IDLBitRange),
    Indexed(IDLBitRange),
}

#[derive(Debug)]
pub struct IdRawEntry {
    id: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IdxMeta {
    pub idxkeys: Map<IdxKey, IdxSlope>,
}

impl IdxMeta {
    pub fn new(idxkeys: Map<IdxKey, IdxSlope>) -> Self {
        IdxMeta { idxkeys }
    }
}

#[derive(Clone)]
pub struct BackendConfig {
    path: String,
    pool_size: u32,
    db_name: &'static str,
    fstype: FsType,
    // Cachesizes?
    arcsize: Option<usize>,
}

impl BackendConfig {
    pub fn new(path: &str, pool_size: u32, fstype: FsType, arcsize: Option<usize>) -> Self {
        BackendConfig {
            pool_size,
            path: path.to_string(),
            db_name: "main",
            fstype,
            arcsize,
        }
    }

    pub(crate) fn new_test(db_name: &'static str) -> Self {
        BackendConfig {
            pool_size: 1,
            path: "".to_string(),
            db_name,
            fstype: FsType::Generic,
            arcsize: Some(1024),
        }
    }
}

#[derive(Clone)]
pub struct Backend {
    /// This is the actual datastorage layer.
    idlayer: Arc<IdlArcSqlite>,
    /// This is a copy-on-write cache of the index metadata that has been
    /// extracted from attributes set, in the correct format for the backend
    /// to consume. We use it to extract indexes from entries during write paths
    /// and to allow the front end to know what indexes exist during a read.
    idxmeta: Arc<CowCell<IdxMeta>>,
    /// The current state of the replication update vector. This is effectively a
    /// time series index of the full list of all changelog entries and what entries
    /// that are part of that change.
    ruv: Arc<ReplicationUpdateVector>,
    cfg: BackendConfig,
}

pub struct BackendReadTransaction<'a> {
    idlayer: IdlArcSqliteReadTransaction<'a>,
    idxmeta: CowCellReadTxn<IdxMeta>,
    ruv: ReplicationUpdateVectorReadTransaction<'a>,
}

unsafe impl<'a> Sync for BackendReadTransaction<'a> {}

unsafe impl<'a> Send for BackendReadTransaction<'a> {}

pub struct BackendWriteTransaction<'a> {
    idlayer: IdlArcSqliteWriteTransaction<'a>,
    idxmeta: CowCellReadTxn<IdxMeta>,
    ruv: ReplicationUpdateVectorWriteTransaction<'a>,
    idxmeta_wr: CowCellWriteTxn<'a, IdxMeta>,
}

impl IdRawEntry {
    fn into_dbentry(self) -> Result<(u64, DbEntry), OperationError> {
        serde_json::from_slice(self.data.as_slice())
            .map_err(|e| {
                admin_error!(?e, "Serde JSON Error");
                OperationError::SerdeJsonError
            })
            .map(|dbe| (self.id, dbe))
    }

    fn into_entry(self) -> Result<Entry<EntrySealed, EntryCommitted>, OperationError> {
        let db_e = serde_json::from_slice(self.data.as_slice()).map_err(|e| {
            admin_error!(?e, id = %self.id, "Serde JSON Error");
            let raw_str = String::from_utf8_lossy(self.data.as_slice());
            debug!(raw = %raw_str);
            OperationError::SerdeJsonError
        })?;
        // let id = u64::try_from(self.id).map_err(|_| OperationError::InvalidEntryId)?;
        Entry::from_dbentry(db_e, self.id).ok_or(OperationError::CorruptedEntry(self.id))
    }
}

pub trait BackendTransaction {
    type IdlLayerType: IdlArcSqliteTransaction;
    fn get_idlayer(&mut self) -> &mut Self::IdlLayerType;

    type RuvType: ReplicationUpdateVectorTransaction;
    fn get_ruv(&mut self) -> &mut Self::RuvType;

    fn get_idxmeta_ref(&self) -> &IdxMeta;

    /// Recursively apply a filter, transforming into IdList's on the way. This builds a query
    /// execution log, so that it can be examined how an operation proceeded.
    #[allow(clippy::cognitive_complexity)]
    #[instrument(level = "debug", name = "be::filter2idl", skip_all)]
    fn filter2idl(
        &mut self,
        filt: &FilterResolved,
        thres: usize,
    ) -> Result<(IdList, FilterPlan), OperationError> {
        Ok(match filt {
            FilterResolved::Eq(attr, value, idx) => {
                if idx.is_some() {
                    // Get the idx_key
                    let idx_key = value.get_idx_eq_key();
                    // Get the idl for this
                    match self
                        .get_idlayer()
                        .get_idl(attr, IndexType::Equality, &idx_key)?
                    {
                        Some(idl) => (
                            IdList::Indexed(idl),
                            FilterPlan::EqIndexed(attr.clone(), idx_key),
                        ),
                        None => (IdList::AllIds, FilterPlan::EqCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::AllIds, FilterPlan::EqUnindexed(attr.clone()))
                }
            }
            FilterResolved::Sub(attr, subvalue, idx) => {
                if idx.is_some() {
                    // Get the idx_key
                    let idx_key = subvalue.get_idx_sub_key();
                    // Get the idl for this
                    match self
                        .get_idlayer()
                        .get_idl(attr, IndexType::SubString, &idx_key)?
                    {
                        Some(idl) => (
                            IdList::Indexed(idl),
                            FilterPlan::SubIndexed(attr.clone(), idx_key),
                        ),
                        None => (IdList::AllIds, FilterPlan::SubCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::AllIds, FilterPlan::SubUnindexed(attr.clone()))
                }
            }
            FilterResolved::Pres(attr, idx) => {
                if idx.is_some() {
                    // Get the idl for this
                    match self.get_idlayer().get_idl(attr, IndexType::Presence, "_")? {
                        Some(idl) => (IdList::Indexed(idl), FilterPlan::PresIndexed(attr.clone())),
                        None => (IdList::AllIds, FilterPlan::PresCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::AllIds, FilterPlan::PresUnindexed(attr.clone()))
                }
            }
            FilterResolved::LessThan(attr, _subvalue, _idx) => {
                // We have no process for indexing this right now.
                (IdList::AllIds, FilterPlan::LessThanUnindexed(attr.clone()))
            }
            FilterResolved::Or(l, _) => {
                // Importantly if this has no inner elements, this returns
                // an empty list.
                let mut plan = Vec::new();
                let mut result = IDLBitRange::new();
                let mut partial = false;
                let mut threshold = false;
                // For each filter in l
                for f in l.iter() {
                    // get their idls
                    match self.filter2idl(f, thres)? {
                        (IdList::Indexed(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                        }
                        (IdList::Partial(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                            partial = true;
                        }
                        (IdList::PartialThreshold(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                            partial = true;
                            threshold = true;
                        }
                        (IdList::AllIds, fp) => {
                            plan.push(fp);
                            // If we find anything unindexed, the whole term is unindexed.
                            filter_trace!("Term {:?} is AllIds, shortcut return", f);
                            let setplan = FilterPlan::OrUnindexed(plan);
                            return Ok((IdList::AllIds, setplan));
                        }
                    }
                } // end or.iter()
                  // If we got here, every term must have been indexed or partial indexed.
                if partial {
                    if threshold {
                        let setplan = FilterPlan::OrPartialThreshold(plan);
                        (IdList::PartialThreshold(result), setplan)
                    } else {
                        let setplan = FilterPlan::OrPartial(plan);
                        (IdList::Partial(result), setplan)
                    }
                } else {
                    let setplan = FilterPlan::OrIndexed(plan);
                    (IdList::Indexed(result), setplan)
                }
            }
            FilterResolved::And(l, _) => {
                // This algorithm is a little annoying. I couldn't get it to work with iter and
                // folds due to the logic needed ...

                // First, setup the two filter lists. We always apply AndNot after positive
                // and terms.
                let (f_andnot, f_rem): (Vec<_>, Vec<_>) = l.iter().partition(|f| f.is_andnot());

                // We make this an iter, so everything comes off in order. if we used pop it means we
                // pull from the tail, which is the WORST item to start with!
                let mut f_rem_iter = f_rem.iter();

                // Setup the initial result.
                let (mut cand_idl, fp) = match f_rem_iter.next() {
                    Some(f) => self.filter2idl(f, thres)?,
                    None => {
                        filter_warn!(
                            "And filter was empty, or contains only AndNot, can not evaluate."
                        );
                        return Ok((IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid));
                    }
                };

                // Setup the counter of terms we have left to evaluate.
                // This is used so that we shortcut return ONLY when we really do have
                // more terms remaining.
                let mut f_rem_count = f_rem.len() + f_andnot.len() - 1;

                // Setup the query plan tracker
                let mut plan = vec![fp];

                match &cand_idl {
                    IdList::Indexed(idl) | IdList::Partial(idl) | IdList::PartialThreshold(idl) => {
                        // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                        // But we only do this when there are actually multiple elements in the and,
                        // because an and with 1 element now is FULLY resolved.
                        if idl.below_threshold(thres) && f_rem_count > 0 {
                            let setplan = FilterPlan::AndPartialThreshold(plan);
                            return Ok((IdList::PartialThreshold(idl.clone()), setplan));
                        } else if idl.is_empty() {
                            // Regardless of the input state, if it's empty, this can never
                            // be satisfied, so return we are indexed and complete.
                            let setplan = FilterPlan::AndEmptyCand(plan);
                            return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                        }
                    }
                    IdList::AllIds => {}
                }

                // Now, for all remaining,
                for f in f_rem_iter {
                    f_rem_count -= 1;
                    let (inter, fp) = self.filter2idl(f, thres)?;
                    plan.push(fp);
                    cand_idl = match (cand_idl, inter) {
                        (IdList::Indexed(ia), IdList::Indexed(ib)) => {
                            let r = ia & ib;
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else if r.is_empty() {
                                // Regardless of the input state, if it's empty, this can never
                                // be satisfied, so return we are indexed and complete.
                                let setplan = FilterPlan::AndEmptyCand(plan);
                                return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                            } else {
                                IdList::Indexed(r)
                            }
                        }
                        (IdList::Indexed(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::Indexed(ib))
                        | (IdList::Partial(ia), IdList::Partial(ib)) => {
                            let r = ia & ib;
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::Partial(r)
                            }
                        }
                        (IdList::Indexed(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Indexed(ib))
                        | (IdList::PartialThreshold(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::PartialThreshold(ib)) => {
                            let r = ia & ib;
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::PartialThreshold(r)
                            }
                        }
                        (IdList::Indexed(i), IdList::AllIds)
                        | (IdList::AllIds, IdList::Indexed(i))
                        | (IdList::Partial(i), IdList::AllIds)
                        | (IdList::AllIds, IdList::Partial(i)) => IdList::Partial(i),
                        (IdList::PartialThreshold(i), IdList::AllIds)
                        | (IdList::AllIds, IdList::PartialThreshold(i)) => {
                            IdList::PartialThreshold(i)
                        }
                        (IdList::AllIds, IdList::AllIds) => IdList::AllIds,
                    };
                }

                // debug!("partial cand set ==> {:?}", cand_idl);

                for f in f_andnot.iter() {
                    f_rem_count -= 1;
                    let f_in = match f {
                        FilterResolved::AndNot(f_in, _) => f_in,
                        _ => {
                            filter_error!(
                                "Invalid server state, a cand filter leaked to andnot set!"
                            );
                            return Err(OperationError::InvalidState);
                        }
                    };
                    let (inter, fp) = self.filter2idl(f_in, thres)?;
                    // It's an and not, so we need to wrap the plan accordingly.
                    plan.push(FilterPlan::AndNot(Box::new(fp)));
                    cand_idl = match (cand_idl, inter) {
                        (IdList::Indexed(ia), IdList::Indexed(ib)) => {
                            let r = ia.andnot(ib);
                            /*
                            // Don't trigger threshold on and nots if fully indexed.
                            if r.below_threshold(thres) {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                return Ok(IdList::PartialThreshold(r));
                            } else {
                                IdList::Indexed(r)
                            }
                            */
                            IdList::Indexed(r)
                        }
                        (IdList::Indexed(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::Indexed(ib))
                        | (IdList::Partial(ia), IdList::Partial(ib)) => {
                            let r = ia.andnot(ib);
                            // DO trigger threshold on partials, because we have to apply the filter
                            // test anyway, so we may as well shortcut at this point.
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::Partial(r)
                            }
                        }
                        (IdList::Indexed(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Indexed(ib))
                        | (IdList::PartialThreshold(ia), IdList::PartialThreshold(ib))
                        | (IdList::PartialThreshold(ia), IdList::Partial(ib))
                        | (IdList::Partial(ia), IdList::PartialThreshold(ib)) => {
                            let r = ia.andnot(ib);
                            // DO trigger threshold on partials, because we have to apply the filter
                            // test anyway, so we may as well shortcut at this point.
                            if r.below_threshold(thres) && f_rem_count > 0 {
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IdList::PartialThreshold(r), setplan));
                            } else {
                                IdList::PartialThreshold(r)
                            }
                        }

                        (IdList::Indexed(_), IdList::AllIds)
                        | (IdList::AllIds, IdList::Indexed(_))
                        | (IdList::Partial(_), IdList::AllIds)
                        | (IdList::AllIds, IdList::Partial(_))
                        | (IdList::PartialThreshold(_), IdList::AllIds)
                        | (IdList::AllIds, IdList::PartialThreshold(_)) => {
                            // We could actually generate allids here
                            // and then try to reduce the and-not set, but
                            // for now we just return all ids.
                            IdList::AllIds
                        }
                        (IdList::AllIds, IdList::AllIds) => IdList::AllIds,
                    };
                }

                // What state is the final cand idl in?
                let setplan = match cand_idl {
                    IdList::Indexed(_) => FilterPlan::AndIndexed(plan),
                    IdList::Partial(_) | IdList::PartialThreshold(_) => {
                        FilterPlan::AndPartial(plan)
                    }
                    IdList::AllIds => FilterPlan::AndUnindexed(plan),
                };

                // Finally, return the result.
                // debug!("final cand set ==> {:?}", cand_idl);
                (cand_idl, setplan)
            } // end and
            FilterResolved::Inclusion(l, _) => {
                // For inclusion to be valid, every term must have *at least* one element present.
                // This really relies on indexing, and so it's internal only - generally only
                // for fully indexed existence queries, such as from refint.

                // This has a lot in common with an And and Or but not really quite either.
                let mut plan = Vec::new();
                let mut result = IDLBitRange::new();
                // For each filter in l
                for f in l.iter() {
                    // get their idls
                    match self.filter2idl(f, thres)? {
                        (IdList::Indexed(idl), fp) => {
                            plan.push(fp);
                            if idl.is_empty() {
                                // It's empty, so something is missing. Bail fast.
                                filter_trace!("Inclusion is unable to proceed - an empty (missing) item was found!");
                                let setplan = FilterPlan::InclusionIndexed(plan);
                                return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                            } else {
                                result = result | idl;
                            }
                        }
                        (_, fp) => {
                            plan.push(fp);
                            filter_error!(
                                "Inclusion is unable to proceed - all terms must be fully indexed!"
                            );
                            let setplan = FilterPlan::InclusionInvalid(plan);
                            return Ok((IdList::Partial(IDLBitRange::new()), setplan));
                        }
                    }
                } // end or.iter()
                  // If we got here, every term must have been indexed
                let setplan = FilterPlan::InclusionIndexed(plan);
                (IdList::Indexed(result), setplan)
            }
            // So why does this return empty? Normally we actually process an AndNot in the context
            // of an "AND" query, but if it's used anywhere else IE the root filter, then there is
            // no other set to exclude - therefore it's empty set. Additionally, even in an OR query
            // the AndNot will be skipped as an empty set for the same reason.
            FilterResolved::AndNot(_f, _) => {
                // get the idl for f
                // now do andnot?
                filter_error!("Requested a top level or isolated AndNot, returning empty");
                (IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid)
            }
        })
    }

    #[instrument(level = "debug", name = "be::search", skip_all)]
    fn search(
        &mut self,
        erl: &Limits,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let _entered = trace_span!("be::search").entered();
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.

        debug!(filter_optimised = ?filt);

        let (idl, fplan) = trace_span!("be::search -> filter2idl")
            .in_scope(|| self.filter2idl(filt.to_inner(), FILTER_SEARCH_TEST_THRESHOLD))?;

        debug!(filter_executed_plan = ?fplan);

        match &idl {
            IdList::AllIds => {
                if !erl.unindexed_allow {
                    admin_error!(
                        "filter (search) is fully unindexed, and not allowed by resource limits"
                    );
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::Partial(idl_br) => {
                // if idl_br.len() > erl.search_max_filter_test {
                if !idl_br.below_threshold(erl.search_max_filter_test) {
                    admin_error!("filter (search) is partial indexed and greater than search_max_filter_test allowed by resource limits");
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::PartialThreshold(_) => {
                // Since we opted for this, this is not the fault
                // of the user and we should not penalise them by limiting on partial.
            }
            IdList::Indexed(idl_br) => {
                // We know this is resolved here, so we can attempt the limit
                // check. This has to fold the whole index, but you know, class=pres is
                // indexed ...
                // if idl_br.len() > erl.search_max_results {
                if !idl_br.below_threshold(erl.search_max_results) {
                    admin_error!("filter (search) is indexed and greater than search_max_results allowed by resource limits");
                    return Err(OperationError::ResourceLimit);
                }
            }
        };

        let entries = self.get_idlayer().get_identry(&idl).map_err(|e| {
            admin_error!(?e, "get_identry failed");
            e
        })?;

        let entries_filtered = match idl {
            IdList::AllIds => trace_span!("be::search<entry::ftest::allids>").in_scope(|| {
                entries
                    .into_iter()
                    .filter(|e| e.entry_match_no_index(filt))
                    .collect()
            }),
            IdList::Partial(_) => trace_span!("be::search<entry::ftest::partial>").in_scope(|| {
                entries
                    .into_iter()
                    .filter(|e| e.entry_match_no_index(filt))
                    .collect()
            }),
            IdList::PartialThreshold(_) => trace_span!("be::search<entry::ftest::thresh>")
                .in_scope(|| {
                    entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(filt))
                        .collect()
                }),
            // Since the index fully resolved, we can shortcut the filter test step here!
            IdList::Indexed(_) => {
                filter_trace!("filter (search) was fully indexed 👏");
                entries
            }
        };

        // If the idl was not indexed, apply the resource limit now. Avoid the needless match since the
        // if statement is quick.
        if entries_filtered.len() > erl.search_max_results {
            admin_error!("filter (search) is resolved and greater than search_max_results allowed by resource limits");
            return Err(OperationError::ResourceLimit);
        }

        Ok(entries_filtered)
    }

    /// Given a filter, assert some condition exists.
    /// Basically, this is a specialised case of search, where we don't need to
    /// load any candidates if they match. This is heavily used in uuid
    /// refint and attr uniqueness.
    #[instrument(level = "debug", name = "be::exists", skip_all)]
    fn exists(
        &mut self,
        erl: &Limits,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<bool, OperationError> {
        debug!(filter_optimised = ?filt);

        // Using the indexes, resolve the IdList here, or AllIds.
        // Also get if the filter was 100% resolved or not.
        let (idl, fplan) = self.filter2idl(filt.to_inner(), FILTER_EXISTS_TEST_THRESHOLD)?;

        debug!(filter_executed_plan = ?fplan);

        // Apply limits to the IdList.
        match &idl {
            IdList::AllIds => {
                if !erl.unindexed_allow {
                    admin_error!(
                        "filter (exists) is fully unindexed, and not allowed by resource limits"
                    );
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::Partial(idl_br) => {
                if !idl_br.below_threshold(erl.search_max_filter_test) {
                    admin_error!("filter (exists) is partial indexed and greater than search_max_filter_test allowed by resource limits");
                    return Err(OperationError::ResourceLimit);
                }
            }
            IdList::PartialThreshold(_) => {
                // Since we opted for this, this is not the fault
                // of the user and we should not penalise them.
            }
            IdList::Indexed(_) => {}
        }

        // Now, check the idl -- if it's fully resolved, we can skip this because the query
        // was fully indexed.
        match &idl {
            IdList::Indexed(idl) => Ok(!idl.is_empty()),
            _ => {
                let entries = self.get_idlayer().get_identry(&idl).map_err(|e| {
                    admin_error!(?e, "get_identry failed");
                    e
                })?;

                // if not 100% resolved query, apply the filter test.
                let entries_filtered: Vec<_> =
                    trace_span!("be::exists<entry::ftest>").in_scope(|| {
                        entries
                            .into_iter()
                            .filter(|e| e.entry_match_no_index(filt))
                            .collect()
                    });

                Ok(!entries_filtered.is_empty())
            }
        } // end match idl
    }

    fn verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        self.get_idlayer().verify()
    }

    fn verify_entry_index(
        &mut self,
        e: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<(), ConsistencyError> {
        // First, check our references in name2uuid, uuid2spn and uuid2rdn
        if e.mask_recycled_ts().is_some() {
            let e_uuid = e.get_uuid();
            // We only check these on live entries.
            let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(None, Some(e));

            let n2u_set = match (n2u_add, n2u_rem) {
                (Some(set), None) => set,
                (_, _) => {
                    admin_error!("Invalid idx_name2uuid_diff state");
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };

            // If the set.len > 1, check each item.
            n2u_set
                .iter()
                .try_for_each(|name| match self.get_idlayer().name2uuid(name) {
                    Ok(Some(idx_uuid)) => {
                        if idx_uuid == e_uuid {
                            Ok(())
                        } else {
                            admin_error!("Invalid name2uuid state -> incorrect uuid association");
                            Err(ConsistencyError::BackendIndexSync)
                        }
                    }
                    r => {
                        admin_error!(state = ?r, "Invalid name2uuid state");
                        Err(ConsistencyError::BackendIndexSync)
                    }
                })?;

            let spn = e.get_uuid2spn();
            match self.get_idlayer().uuid2spn(e_uuid) {
                Ok(Some(idx_spn)) => {
                    if spn != idx_spn {
                        admin_error!("Invalid uuid2spn state -> incorrect idx spn value");
                        return Err(ConsistencyError::BackendIndexSync);
                    }
                }
                r => {
                    admin_error!(state = ?r, "Invalid uuid2spn state");
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };

            let rdn = e.get_uuid2rdn();
            match self.get_idlayer().uuid2rdn(e_uuid) {
                Ok(Some(idx_rdn)) => {
                    if rdn != idx_rdn {
                        admin_error!("Invalid uuid2rdn state -> incorrect idx rdn value");
                        return Err(ConsistencyError::BackendIndexSync);
                    }
                }
                r => {
                    admin_error!(state = ?r, "Invalid uuid2rdn state");
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };
        }

        // Check the other entry:attr indexes are valid
        //
        // This is actually pretty hard to check, because we can check a value *should*
        // exist, but not that a value should NOT be present in the index. Thought needed ...

        // Got here? Ok!
        Ok(())
    }

    fn verify_indexes(&mut self) -> Vec<Result<(), ConsistencyError>> {
        let idl = IdList::AllIds;
        let entries = match self.get_idlayer().get_identry(&idl) {
            Ok(s) => s,
            Err(e) => {
                admin_error!(?e, "get_identry failure");
                return vec![Err(ConsistencyError::Unknown)];
            }
        };

        let r = entries.iter().try_for_each(|e| self.verify_entry_index(e));

        if r.is_err() {
            vec![r]
        } else {
            Vec::new()
        }
    }

    fn verify_ruv(&mut self, results: &mut Vec<Result<(), ConsistencyError>>) {
        // The way we verify this is building a whole second RUV and then comparing it.
        let idl = IdList::AllIds;
        let entries = match self.get_idlayer().get_identry(&idl) {
            Ok(ent) => ent,
            Err(e) => {
                results.push(Err(ConsistencyError::Unknown));
                admin_error!(?e, "get_identry failed");
                return;
            }
        };

        self.get_ruv().verify(&entries, results);
    }

    fn backup(&mut self, dst_path: &str) -> Result<(), OperationError> {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let idl = IdList::AllIds;
        let idlayer = self.get_idlayer();
        let raw_entries: Vec<IdRawEntry> = idlayer.get_identry_raw(&idl)?;

        let entries: Result<Vec<DbEntry>, _> = raw_entries
            .iter()
            .map(|id_ent| {
                serde_json::from_slice(id_ent.data.as_slice())
                    .map_err(|_| OperationError::SerdeJsonError) // log?
            })
            .collect();

        let entries = entries?;

        let db_s_uuid = idlayer
            .get_db_s_uuid()
            .and_then(|u| u.ok_or(OperationError::InvalidDbState))?;
        let db_d_uuid = idlayer
            .get_db_d_uuid()
            .and_then(|u| u.ok_or(OperationError::InvalidDbState))?;
        let db_ts_max = idlayer
            .get_db_ts_max()
            .and_then(|u| u.ok_or(OperationError::InvalidDbState))?;

        let bak = DbBackup::V2 {
            db_s_uuid,
            db_d_uuid,
            db_ts_max,
            entries,
        };

        let serialized_entries_str = serde_json::to_string(&bak).map_err(|e| {
            admin_error!(?e, "serde error");
            OperationError::SerdeJsonError
        })?;

        fs::write(dst_path, serialized_entries_str)
            .map(|_| ())
            .map_err(|e| {
                admin_error!(?e, "fs::write error");
                OperationError::FsError
            })
    }

    fn name2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        self.get_idlayer().name2uuid(name)
    }

    fn externalid2uuid(&mut self, name: &str) -> Result<Option<Uuid>, OperationError> {
        self.get_idlayer().externalid2uuid(name)
    }

    fn uuid2spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        self.get_idlayer().uuid2spn(uuid)
    }

    fn uuid2rdn(&mut self, uuid: Uuid) -> Result<Option<String>, OperationError> {
        self.get_idlayer().uuid2rdn(uuid)
    }
}

impl<'a> BackendTransaction for BackendReadTransaction<'a> {
    type IdlLayerType = IdlArcSqliteReadTransaction<'a>;
    type RuvType = ReplicationUpdateVectorReadTransaction<'a>;

    fn get_idlayer(&mut self) -> &mut IdlArcSqliteReadTransaction<'a> {
        &mut self.idlayer
    }

    fn get_ruv(&mut self) -> &mut ReplicationUpdateVectorReadTransaction<'a> {
        &mut self.ruv
    }

    fn get_idxmeta_ref(&self) -> &IdxMeta {
        &self.idxmeta
    }
}

impl<'a> BackendReadTransaction<'a> {
    pub fn list_indexes(&mut self) -> Result<Vec<String>, OperationError> {
        self.get_idlayer().list_idxs()
    }

    pub fn list_id2entry(&mut self) -> Result<Vec<(u64, String)>, OperationError> {
        self.get_idlayer().list_id2entry()
    }

    pub fn list_index_content(
        &mut self,
        index_name: &str,
    ) -> Result<Vec<(String, IDLBitRange)>, OperationError> {
        self.get_idlayer().list_index_content(index_name)
    }

    pub fn get_id2entry(&mut self, id: u64) -> Result<(u64, String), OperationError> {
        self.get_idlayer().get_id2entry(id)
    }
}

impl<'a> BackendTransaction for BackendWriteTransaction<'a> {
    type IdlLayerType = IdlArcSqliteWriteTransaction<'a>;
    type RuvType = ReplicationUpdateVectorWriteTransaction<'a>;

    fn get_idlayer(&mut self) -> &mut IdlArcSqliteWriteTransaction<'a> {
        &mut self.idlayer
    }

    fn get_ruv(&mut self) -> &mut ReplicationUpdateVectorWriteTransaction<'a> {
        &mut self.ruv
    }

    fn get_idxmeta_ref(&self) -> &IdxMeta {
        &self.idxmeta
    }
}

impl<'a> BackendWriteTransaction<'a> {
    #[instrument(level = "debug", name = "be::create", skip_all)]
    pub fn create(
        &mut self,
        cid: &Cid,
        entries: Vec<Entry<EntrySealed, EntryNew>>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        if entries.is_empty() {
            admin_error!("No entries provided to BE to create, invalid server call!");
            return Err(OperationError::EmptyRequest);
        }

        // Check that every entry has a change associated
        // that matches the cid?
        entries.iter().try_for_each(|e| {
            if e.get_changestate().contains_tail_cid(cid) {
                Ok(())
            } else {
                admin_error!(
                    "Entry changelog does not contain a change related to this transaction"
                );
                Err(OperationError::ReplEntryNotChanged)
            }
        })?;

        // Now, assign id's to all the new entries.

        let mut id_max = self.idlayer.get_id2entry_max_id()?;
        let c_entries: Vec<_> = entries
            .into_iter()
            .map(|e| {
                id_max += 1;
                e.into_sealed_committed_id(id_max)
            })
            .collect();

        // All good, lets update the RUV.
        // This auto compresses.
        let ruv_idl = IDLBitRange::from_iter(c_entries.iter().map(|e| e.get_id()));

        self.get_ruv().insert_change(cid, ruv_idl)?;

        self.idlayer.write_identries(c_entries.iter())?;

        self.idlayer.set_id2entry_max_id(id_max);

        // Now update the indexes as required.
        for e in c_entries.iter() {
            self.entry_index(None, Some(e))?
        }

        Ok(c_entries)
    }

    #[instrument(level = "debug", name = "be::create", skip_all)]
    /// This is similar to create, but used in the replication path as it skips the
    /// modification of the RUV and the checking of CIDs since these actions are not
    /// required during a replication refresh (else we'd create an infinite replication
    /// loop.)
    pub fn refresh(
        &mut self,
        entries: Vec<Entry<EntrySealed, EntryNew>>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        if entries.is_empty() {
            admin_error!("No entries provided to BE to create, invalid server call!");
            return Err(OperationError::EmptyRequest);
        }

        // Assign id's to all the new entries.
        let mut id_max = self.idlayer.get_id2entry_max_id()?;
        let c_entries: Vec<_> = entries
            .into_iter()
            .map(|e| {
                id_max += 1;
                e.into_sealed_committed_id(id_max)
            })
            .collect();

        self.idlayer.write_identries(c_entries.iter())?;

        self.idlayer.set_id2entry_max_id(id_max);

        // Now update the indexes as required.
        for e in c_entries.iter() {
            self.entry_index(None, Some(e))?
        }

        Ok(c_entries)
    }

    #[instrument(level = "debug", name = "be::modify", skip_all)]
    pub fn modify(
        &mut self,
        cid: &Cid,
        pre_entries: &[Arc<EntrySealedCommitted>],
        post_entries: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        if post_entries.is_empty() || pre_entries.is_empty() {
            admin_error!("No entries provided to BE to modify, invalid server call!");
            return Err(OperationError::EmptyRequest);
        }

        assert!(post_entries.len() == pre_entries.len());

        post_entries.iter().try_for_each(|e| {
            if e.get_changestate().contains_tail_cid(cid) {
                Ok(())
            } else {
                admin_error!(
                    "Entry changelog does not contain a change related to this transaction"
                );
                Err(OperationError::ReplEntryNotChanged)
            }
        })?;

        // All good, lets update the RUV.
        // This auto compresses.
        let ruv_idl = IDLBitRange::from_iter(post_entries.iter().map(|e| e.get_id()));
        self.get_ruv().insert_change(cid, ruv_idl)?;

        // Now, given the list of id's, update them
        self.get_idlayer().write_identries(post_entries.iter())?;

        // Finally, we now reindex all the changed entries. We do this by iterating and zipping
        // over the set, because we know the list is in the same order.
        pre_entries
            .iter()
            .zip(post_entries.iter())
            .try_for_each(|(pre, post)| self.entry_index(Some(pre.as_ref()), Some(post)))
    }

    #[instrument(level = "debug", name = "be::reap_tombstones", skip_all)]
    pub fn reap_tombstones(&mut self, cid: &Cid) -> Result<usize, OperationError> {
        // We plan to clear the RUV up to this cid. So we need to build an IDL
        // of all the entries we need to examine.
        let idl = self.get_ruv().trim_up_to(cid).map_err(|e| {
            admin_error!(?e, "failed to trim RUV to {:?}", cid);
            e
        })?;

        let entries = self
            .get_idlayer()
            .get_identry(&IdList::Indexed(idl))
            .map_err(|e| {
                admin_error!(?e, "get_identry failed");
                e
            })?;

        if entries.is_empty() {
            admin_info!("No entries affected - reap_tombstones operation success");
            return Ok(0);
        }

        // Now that we have a list of entries we need to partition them into
        // two sets. The entries that are tombstoned and ready to reap_tombstones, and
        // the entries that need to have their change logs trimmed.
        //
        // Remember, these tombstones can be reaped because they were tombstoned at time
        // point 'cid', and since we are now "past" that minimum cid, then other servers
        // will also be trimming these out.
        //
        // Note unlike a changelog impl, we don't need to trim changestates here. We
        // only need the RUV trimmed so that we know if other servers are laggin behind!

        // What entries are tombstones and ready to be deleted?

        let (tombstones, leftover): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|e| e.get_changestate().can_delete(cid));

        let ruv_idls = self.get_ruv().ruv_idls();

        // Assert that anything leftover still either is *alive* OR is a tombstone
        // and has entries in the RUV!

        if !leftover
            .iter()
            .all(|e| e.get_changestate().is_live() || ruv_idls.contains(e.get_id()))
        {
            admin_error!("Left over entries may be orphaned due to missing RUV entries");
            return Err(OperationError::ReplInvalidRUVState);
        }

        // Now setup to reap_tombstones the tombstones. Remember, in the post cleanup, it's could
        // now have been trimmed to a point we can purge them!

        // Assert the id's exist on the entry.
        let id_list: IDLBitRange = tombstones.iter().map(|e| e.get_id()).collect();

        // Ensure nothing here exists in the RUV index, else it means
        // we didn't trim properly, or some other state violation has occurred.
        if !((&ruv_idls & &id_list).is_empty()) {
            admin_error!("RUV still contains entries that are going to be removed.");
            return Err(OperationError::ReplInvalidRUVState);
        }

        // Now, given the list of id's, reap_tombstones them.
        let sz = id_list.len();
        self.get_idlayer().delete_identry(id_list.into_iter())?;

        // Finally, purge the indexes from the entries we removed. These still have
        // indexes due to class=tombstone.
        tombstones
            .iter()
            .try_for_each(|e| self.entry_index(Some(e), None))?;

        Ok(sz)
    }

    #[instrument(level = "debug", name = "be::update_idxmeta", skip_all)]
    pub fn update_idxmeta(&mut self, idxkeys: Vec<IdxKey>) -> Result<(), OperationError> {
        if self.is_idx_slopeyness_generated()? {
            trace!("Indexing slopes available");
        } else {
            admin_warn!(
                "No indexing slopes available. You should consider reindexing to generate these"
            );
        };

        // Setup idxkeys here. By default we set these all to "max slope" aka
        // all indexes are "equal" but also worse case unless analysed. If they
        // have been analysed, we can set the slope factor into here.
        let idxkeys: Result<Map<_, _>, _> = idxkeys
            .into_iter()
            .map(|k| self.get_idx_slope(&k).map(|slope| (k, slope)))
            .collect();

        let mut idxkeys = idxkeys?;

        std::mem::swap(&mut self.idxmeta_wr.deref_mut().idxkeys, &mut idxkeys);
        Ok(())
    }

    // Should take a mut index set, and then we write the whole thing back
    // in a single stripe.
    //
    // So we need a cache, which we load indexes into as we do ops, then we
    // modify them.
    //
    // At the end, we flush those cchange outs in a single run.
    // For create this is probably a
    // TODO: Can this be improved?
    #[allow(clippy::cognitive_complexity)]
    fn entry_index(
        &mut self,
        pre: Option<&Entry<EntrySealed, EntryCommitted>>,
        post: Option<&Entry<EntrySealed, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        let (e_uuid, e_id, uuid_same) = match (pre, post) {
            (None, None) => {
                admin_error!("Invalid call to entry_index - no entries provided");
                return Err(OperationError::InvalidState);
            }
            (Some(pre), None) => {
                trace!("Attempting to remove entry indexes");
                (pre.get_uuid(), pre.get_id(), true)
            }
            (None, Some(post)) => {
                trace!("Attempting to create entry indexes");
                (post.get_uuid(), post.get_id(), true)
            }
            (Some(pre), Some(post)) => {
                trace!("Attempting to modify entry indexes");
                assert!(pre.get_id() == post.get_id());
                (
                    post.get_uuid(),
                    post.get_id(),
                    pre.get_uuid() == post.get_uuid(),
                )
            }
        };

        // Update the names/uuid maps. These have to mask out entries
        // that are recycled or tombstones, so these pretend as "deleted"
        // and can trigger correct actions.
        //

        let mask_pre = pre.and_then(|e| e.mask_recycled_ts());
        let mask_pre = if !uuid_same {
            // Okay, so if the uuids are different this is probably from
            // a replication conflict.  We can't just use the normal none/some
            // check from the Entry::idx functions as they only yield partial
            // changes. Because the uuid is changing, we have to treat pre
            // as a deleting entry, regardless of what state post is in.
            let uuid = mask_pre.map(|e| e.get_uuid()).ok_or_else(|| {
                admin_error!("Invalid entry state - possible memory corruption");
                OperationError::InvalidState
            })?;

            let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(mask_pre, None);
            // There will never be content to add.
            assert!(n2u_add.is_none());

            let (eid2u_add, eid2u_rem) = Entry::idx_externalid2uuid_diff(mask_pre, None);
            // There will never be content to add.
            assert!(eid2u_add.is_none());

            let u2s_act = Entry::idx_uuid2spn_diff(mask_pre, None);
            let u2r_act = Entry::idx_uuid2rdn_diff(mask_pre, None);

            trace!(?n2u_rem, ?eid2u_rem, ?u2s_act, ?u2r_act,);

            // Write the changes out to the backend
            if let Some(rem) = n2u_rem {
                self.idlayer.write_name2uuid_rem(rem)?
            }

            if let Some(rem) = eid2u_rem {
                self.idlayer.write_externalid2uuid_rem(rem)?
            }

            match u2s_act {
                None => {}
                Some(Ok(k)) => self.idlayer.write_uuid2spn(uuid, Some(k))?,
                Some(Err(_)) => self.idlayer.write_uuid2spn(uuid, None)?,
            }

            match u2r_act {
                None => {}
                Some(Ok(k)) => self.idlayer.write_uuid2rdn(uuid, Some(k))?,
                Some(Err(_)) => self.idlayer.write_uuid2rdn(uuid, None)?,
            }
            // Return none, mask_pre is now completed.
            None
        } else {
            // Return the state.
            mask_pre
        };

        let mask_post = post.and_then(|e| e.mask_recycled_ts());
        let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(mask_pre, mask_post);
        let (eid2u_add, eid2u_rem) = Entry::idx_externalid2uuid_diff(mask_pre, mask_post);

        let u2s_act = Entry::idx_uuid2spn_diff(mask_pre, mask_post);
        let u2r_act = Entry::idx_uuid2rdn_diff(mask_pre, mask_post);

        trace!(
            ?n2u_add,
            ?n2u_rem,
            ?eid2u_add,
            ?eid2u_rem,
            ?u2s_act,
            ?u2r_act
        );

        // Write the changes out to the backend
        if let Some(add) = n2u_add {
            self.idlayer.write_name2uuid_add(e_uuid, add)?
        }
        if let Some(rem) = n2u_rem {
            self.idlayer.write_name2uuid_rem(rem)?
        }

        if let Some(add) = eid2u_add {
            self.idlayer.write_externalid2uuid_add(e_uuid, add)?
        }
        if let Some(rem) = eid2u_rem {
            self.idlayer.write_externalid2uuid_rem(rem)?
        }

        match u2s_act {
            None => {}
            Some(Ok(k)) => self.idlayer.write_uuid2spn(e_uuid, Some(k))?,
            Some(Err(_)) => self.idlayer.write_uuid2spn(e_uuid, None)?,
        }

        match u2r_act {
            None => {}
            Some(Ok(k)) => self.idlayer.write_uuid2rdn(e_uuid, Some(k))?,
            Some(Err(_)) => self.idlayer.write_uuid2rdn(e_uuid, None)?,
        }

        // Extremely Cursed - Okay, we know that self.idxmeta will NOT be changed
        // in this function, but we need to borrow self as mut for the caches in
        // get_idl to work. As a result, this causes a double borrow. To work around
        // this we discard the lifetime on idxmeta, because we know that it will
        // remain constant for the life of the operation.

        let idxmeta = unsafe { &(*(&self.idxmeta.idxkeys as *const _)) };

        let idx_diff = Entry::idx_diff(idxmeta, pre, post);

        idx_diff.into_iter()
            .try_for_each(|act| {
                match act {
                    Ok((attr, itype, idx_key)) => {
                        trace!("Adding {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match self.idlayer.get_idl(attr, itype, &idx_key)? {
                            Some(mut idl) => {
                                idl.insert_id(e_id);
                                self.idlayer.write_idl(attr, itype, &idx_key, &idl)
                            }
                            None => {
                                warn!(
                                    "WARNING: index {:?} {:?} was not found. YOU MUST REINDEX YOUR DATABASE",
                                    attr, itype
                                );
                                Ok(())
                            }
                        }
                    }
                    Err((attr, itype, idx_key)) => {
                        trace!("Removing {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match self.idlayer.get_idl(attr, itype, &idx_key)? {
                            Some(mut idl) => {
                                idl.remove_id(e_id);
                                self.idlayer.write_idl(attr, itype, &idx_key, &idl)
                            }
                            None => {
                                warn!(
                                    "WARNING: index {:?} {:?} was not found. YOU MUST REINDEX YOUR DATABASE",
                                    attr, itype
                                );
                                Ok(())
                            }
                        }
                    }
                }
            })
        // End try_for_each
    }

    #[allow(dead_code)]
    fn missing_idxs(&mut self) -> Result<Vec<(AttrString, IndexType)>, OperationError> {
        let idx_table_list = self.get_idlayer().list_idxs()?;

        // Turn the vec to a real set
        let idx_table_set: HashSet<_> = idx_table_list.into_iter().collect();

        let missing: Vec<_> = self
            .idxmeta
            .idxkeys
            .keys()
            .filter_map(|ikey| {
                // what would the table name be?
                let tname = format!("idx_{}_{}", ikey.itype.as_idx_str(), ikey.attr.as_str());
                trace!("Checking for {}", tname);

                if idx_table_set.contains(&tname) {
                    None
                } else {
                    Some((ikey.attr.clone(), ikey.itype))
                }
            })
            .collect();
        Ok(missing)
    }

    fn create_idxs(&mut self) -> Result<(), OperationError> {
        // Create name2uuid and uuid2name
        trace!("Creating index -> name2uuid");
        self.idlayer.create_name2uuid()?;

        trace!("Creating index -> externalid2uuid");
        self.idlayer.create_externalid2uuid()?;

        trace!("Creating index -> uuid2spn");
        self.idlayer.create_uuid2spn()?;

        trace!("Creating index -> uuid2rdn");
        self.idlayer.create_uuid2rdn()?;

        self.idxmeta
            .idxkeys
            .keys()
            .try_for_each(|ikey| self.idlayer.create_idx(&ikey.attr, ikey.itype))
    }

    pub fn upgrade_reindex(&mut self, v: i64) -> Result<(), OperationError> {
        let dbv = self.get_db_index_version();
        admin_debug!(?dbv, ?v, "upgrade_reindex");
        if dbv < v {
            limmediate_warning!(
                "NOTICE: A system reindex is required. This may take a long time ...\n"
            );
            self.reindex()?;
            limmediate_warning!("NOTICE: System reindex complete\n");
            self.set_db_index_version(v)
        } else {
            Ok(())
        }
    }

    pub fn reindex(&mut self) -> Result<(), OperationError> {
        // Purge the idxs
        unsafe { self.idlayer.purge_idxs()? };

        // Using the index metadata on the txn, create all our idx tables
        self.create_idxs()?;

        // Now, we need to iterate over everything in id2entry and index them
        // Future idea: Do this in batches of X amount to limit memory
        // consumption.
        let idl = IdList::AllIds;
        let entries = self.idlayer.get_identry(&idl).map_err(|e| {
            admin_error!(err = ?e, "get_identry failure");
            e
        })?;

        let mut count = 0;

        entries
            .iter()
            .try_for_each(|e| {
                count += 1;
                if count % 2500 == 0 {
                    limmediate_warning!("{}", count);
                } else if count % 250 == 0 {
                    limmediate_warning!(".");
                }
                self.entry_index(None, Some(e))
            })
            .map_err(|e| {
                admin_error!("reindex failed -> {:?}", e);
                e
            })?;
        limmediate_warning!(" reindexed {} entries ✅\n", count);
        limmediate_warning!("Optimising Indexes ... ");
        self.idlayer.optimise_dirty_idls();
        limmediate_warning!("done ✅\n");
        limmediate_warning!("Calculating Index Optimisation Slopes ... ");
        self.idlayer.analyse_idx_slopes().map_err(|e| {
            admin_error!(err = ?e, "index optimisation failed");
            e
        })?;
        limmediate_warning!("done ✅\n");
        Ok(())
    }

    fn purge_idxs(&mut self) -> Result<(), OperationError> {
        unsafe { self.get_idlayer().purge_idxs() }
    }

    pub(crate) fn danger_delete_all_db_content(&mut self) -> Result<(), OperationError> {
        unsafe {
            self.get_idlayer()
                .purge_id2entry()
                .and_then(|_| self.purge_idxs())
        }
    }

    #[cfg(test)]
    pub fn load_test_idl(
        &mut self,
        attr: &String,
        itype: IndexType,
        idx_key: &String,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        self.get_idlayer().get_idl(attr, itype, idx_key)
    }

    fn is_idx_slopeyness_generated(&mut self) -> Result<bool, OperationError> {
        self.get_idlayer().is_idx_slopeyness_generated()
    }

    fn get_idx_slope(&mut self, ikey: &IdxKey) -> Result<IdxSlope, OperationError> {
        // Do we have the slopeyness?
        let slope = self
            .get_idlayer()
            .get_idx_slope(ikey)?
            .unwrap_or_else(|| get_idx_slope_default(ikey));
        trace!("index slope - {:?} -> {:?}", ikey, slope);
        Ok(slope)
    }

    pub fn restore(&mut self, src_path: &str) -> Result<(), OperationError> {
        let idlayer = self.get_idlayer();
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let serialized_string = fs::read_to_string(src_path).map_err(|e| {
            admin_error!("fs::read_to_string {:?}", e);
            OperationError::FsError
        })?;

        unsafe { idlayer.purge_id2entry() }.map_err(|e| {
            admin_error!("purge_id2entry failed {:?}", e);
            e
        })?;

        let dbbak_option: Result<DbBackup, serde_json::Error> =
            serde_json::from_str(&serialized_string);

        let dbbak = dbbak_option.map_err(|e| {
            admin_error!("serde_json error {:?}", e);
            OperationError::SerdeJsonError
        })?;

        let dbentries = match dbbak {
            DbBackup::V1(dbentries) => dbentries,
            DbBackup::V2 {
                db_s_uuid,
                db_d_uuid,
                db_ts_max,
                entries,
            } => {
                // Do stuff.
                idlayer.write_db_s_uuid(db_s_uuid)?;
                idlayer.write_db_d_uuid(db_d_uuid)?;
                idlayer.set_db_ts_max(db_ts_max)?;
                entries
            }
        };

        info!("Restoring {} entries ...", dbentries.len());

        // Migrate any v1 entries to v2 if needed.
        let dbentries = dbentries
            .into_iter()
            .map(|dbe| dbe.convert_to_v2())
            .collect::<Result<Vec<_>, _>>()?;

        // Now, we setup all the entries with new ids.
        let mut id_max = 0;
        let identries: Result<Vec<IdRawEntry>, _> = dbentries
            .iter()
            .map(|e| {
                id_max += 1;
                let data = serde_json::to_vec(&e).map_err(|_| OperationError::SerdeCborError)?;
                Ok(IdRawEntry { id: id_max, data })
            })
            .collect();

        idlayer.write_identries_raw(identries?.into_iter())?;

        info!("Restored {} entries", dbentries.len());

        // Reindex now we are loaded.
        self.reindex()?;

        let vr = self.verify();
        if vr.is_empty() {
            Ok(())
        } else {
            Err(OperationError::ConsistencyError(vr))
        }
    }

    #[instrument(level = "debug", name = "be::ruv_rebuild", skip_all)]
    pub fn ruv_rebuild(&mut self) -> Result<(), OperationError> {
        // Rebuild the ruv!
        // For now this has to read from all the entries in the DB, but in the future
        // we'll actually store this properly (?). If it turns out this is really fast
        // we may just rebuild this always on startup.

        // NOTE: An important detail is that we don't rely on indexes here!

        let idl = IdList::AllIds;
        let entries = self.get_idlayer().get_identry(&idl).map_err(|e| {
            admin_error!(?e, "get_identry failed");
            e
        })?;

        self.get_ruv().rebuild(&entries)?;

        Ok(())
    }

    pub fn commit(self) -> Result<(), OperationError> {
        let BackendWriteTransaction {
            idlayer,
            idxmeta: _,
            ruv,
            idxmeta_wr,
        } = self;

        idlayer.commit().map(|()| {
            ruv.commit();
            idxmeta_wr.commit();
        })
    }

    fn reset_db_s_uuid(&mut self) -> Result<Uuid, OperationError> {
        // The value is missing. Generate a new one and store it.
        let nsid = Uuid::new_v4();
        self.get_idlayer().write_db_s_uuid(nsid)?;
        Ok(nsid)
    }

    pub fn get_db_s_uuid(&mut self) -> Uuid {
        #[allow(clippy::expect_used)]
        match self
            .get_idlayer()
            .get_db_s_uuid()
            .expect("DBLayer Error!!!")
        {
            Some(s_uuid) => s_uuid,
            None => self.reset_db_s_uuid().expect("Failed to regenerate S_UUID"),
        }
    }

    /// This generates a new domain UUID and stores it into the database,
    /// returning the new UUID
    fn reset_db_d_uuid(&mut self) -> Result<Uuid, OperationError> {
        let nsid = Uuid::new_v4();
        self.get_idlayer().write_db_d_uuid(nsid)?;
        Ok(nsid)
    }

    /// Manually set a new domain UUID and store it into the DB. This is used
    /// as part of a replication refresh.
    pub fn set_db_d_uuid(&mut self, nsid: Uuid) -> Result<(), OperationError> {
        self.get_idlayer().write_db_d_uuid(nsid)
    }

    /// This pulls the domain UUID from the database
    pub fn get_db_d_uuid(&mut self) -> Uuid {
        #[allow(clippy::expect_used)]
        match self
            .get_idlayer()
            .get_db_d_uuid()
            .expect("DBLayer Error retrieving Domain UUID!!!")
        {
            Some(d_uuid) => d_uuid,
            None => self.reset_db_d_uuid().expect("Failed to regenerate D_UUID"),
        }
    }

    pub fn set_db_ts_max(&mut self, ts: Duration) -> Result<(), OperationError> {
        self.get_idlayer().set_db_ts_max(ts)
    }

    pub fn get_db_ts_max(&mut self, ts: Duration) -> Result<Duration, OperationError> {
        // if none, return ts. If found, return it.
        match self.get_idlayer().get_db_ts_max()? {
            Some(dts) => Ok(dts),
            None => Ok(ts),
        }
    }

    fn get_db_index_version(&mut self) -> i64 {
        self.get_idlayer().get_db_index_version()
    }

    fn set_db_index_version(&mut self, v: i64) -> Result<(), OperationError> {
        self.get_idlayer().set_db_index_version(v)
    }
}

// We have a number of hardcoded, "obvious" slopes that should
// exist. We return these when the analysis has not been run, as
// these are values that are generally "good enough" for most applications
fn get_idx_slope_default(ikey: &IdxKey) -> IdxSlope {
    match (ikey.attr.as_str(), &ikey.itype) {
        ("name", IndexType::Equality)
        | ("spn", IndexType::Equality)
        | ("uuid", IndexType::Equality) => 1,
        ("class", IndexType::Equality) => 180,
        (_, IndexType::Equality) => 45,
        (_, IndexType::SubString) => 90,
        (_, IndexType::Presence) => 90,
    }
}

// In the future this will do the routing between the chosen backends etc.
impl Backend {
    #[instrument(level = "debug", name = "be::new", skip_all)]
    pub fn new(
        mut cfg: BackendConfig,
        // path: &str,
        // mut pool_size: u32,
        // fstype: FsType,
        idxkeys: Vec<IdxKey>,
        vacuum: bool,
    ) -> Result<Self, OperationError> {
        debug!("DB tickets -> {:?}", cfg.pool_size);
        debug!("Profile -> {}", env!("KANIDM_PROFILE_NAME"));
        debug!("CPU Flags -> {}", env!("KANIDM_CPU_FLAGS"));

        // If in memory, reduce pool to 1
        if cfg.path.is_empty() {
            cfg.pool_size = 1;
        }

        // Setup idxkeys here. By default we set these all to "max slope" aka
        // all indexes are "equal" but also worse case unless analysed.
        //
        // During startup this will be "fixed" as the schema core will call reload_idxmeta
        // which will trigger a reload of the analysis data (if present).
        let idxkeys: Map<_, _> = idxkeys
            .into_iter()
            .map(|ikey| {
                let slope = get_idx_slope_default(&ikey);
                (ikey, slope)
            })
            .collect();

        // RUV-TODO
        // Load the replication update vector here. For now we rebuild every startup
        // from the database.
        let ruv = Arc::new(ReplicationUpdateVector::default());

        // this has a ::memory() type, but will path == "" work?
        let idlayer = Arc::new(IdlArcSqlite::new(&cfg, vacuum)?);
        let be = Backend {
            cfg,
            idlayer,
            ruv,
            idxmeta: Arc::new(CowCell::new(IdxMeta::new(idxkeys))),
        };

        // Now complete our setup with a txn
        // In this case we can use an empty idx meta because we don't
        // access any parts of
        // the indexing subsystem here.
        let mut idl_write = be.idlayer.write();
        idl_write
            .setup()
            .and_then(|_| idl_write.commit())
            .map_err(|e| {
                admin_error!(?e, "Failed to setup idlayer");
                e
            })?;

        // Now rebuild the ruv.
        let mut be_write = be.write();
        be_write
            .ruv_rebuild()
            .and_then(|_| be_write.commit())
            .map_err(|e| {
                admin_error!(?e, "Failed to reload ruv");
                e
            })?;

        Ok(be)
    }

    pub fn get_pool_size(&self) -> u32 {
        debug_assert!(self.cfg.pool_size > 0);
        self.cfg.pool_size
    }

    pub fn try_quiesce(&self) {
        self.idlayer.try_quiesce();
    }

    pub fn read(&self) -> BackendReadTransaction {
        BackendReadTransaction {
            idlayer: self.idlayer.read(),
            idxmeta: self.idxmeta.read(),
            ruv: self.ruv.read(),
        }
    }

    pub fn write(&self) -> BackendWriteTransaction {
        BackendWriteTransaction {
            idlayer: self.idlayer.write(),
            idxmeta: self.idxmeta.read(),
            ruv: self.ruv.write(),
            idxmeta_wr: self.idxmeta.write(),
        }
    }

    // Should this actually call the idlayer directly?
    pub fn reset_db_s_uuid(&self) -> Uuid {
        let mut wr = self.write();
        #[allow(clippy::expect_used)]
        let sid = wr
            .reset_db_s_uuid()
            .expect("unable to reset db server uuid");
        #[allow(clippy::expect_used)]
        wr.commit()
            .expect("Unable to commit to backend, can not proceed");
        sid
    }

    /*
    pub fn get_db_s_uuid(&self) -> Uuid {
        let wr = self.write(Set::new());
        wr.reset_db_s_uuid().unwrap()
    }
    */
}

// What are the possible actions we'll receive here?

#[cfg(test)]
mod tests {
    use std::fs;
    use std::iter::FromIterator;
    use std::sync::Arc;
    use std::time::Duration;

    use idlset::v2::IDLBitRange;

    use super::super::entry::{Entry, EntryInit, EntryNew};
    use super::Limits;
    use super::{
        Backend, BackendConfig, BackendTransaction, BackendWriteTransaction, DbBackup, IdList,
        IdxKey, OperationError,
    };
    use crate::prelude::*;
    use crate::repl::cid::Cid;
    use crate::value::{IndexType, PartialValue, Value};

    lazy_static! {
        static ref CID_ZERO: Cid = unsafe { Cid::new_zero() };
        static ref CID_ONE: Cid = unsafe { Cid::new_count(1) };
        static ref CID_TWO: Cid = unsafe { Cid::new_count(2) };
        static ref CID_THREE: Cid = unsafe { Cid::new_count(3) };
    }

    macro_rules! run_test {
        ($test_fn:expr) => {{
            let _ = sketching::test_init();

            // This is a demo idxmeta, purely for testing.
            let idxmeta = vec![
                IdxKey {
                    attr: AttrString::from("name"),
                    itype: IndexType::Equality,
                },
                IdxKey {
                    attr: AttrString::from("name"),
                    itype: IndexType::Presence,
                },
                IdxKey {
                    attr: AttrString::from("name"),
                    itype: IndexType::SubString,
                },
                IdxKey {
                    attr: AttrString::from("uuid"),
                    itype: IndexType::Equality,
                },
                IdxKey {
                    attr: AttrString::from("uuid"),
                    itype: IndexType::Presence,
                },
                IdxKey {
                    attr: AttrString::from("ta"),
                    itype: IndexType::Equality,
                },
                IdxKey {
                    attr: AttrString::from("tb"),
                    itype: IndexType::Equality,
                },
            ];

            let be = Backend::new(BackendConfig::new_test("main"), idxmeta, false)
                .expect("Failed to setup backend");

            let mut be_txn = be.write();

            let r = $test_fn(&mut be_txn);
            // Commit, to guarantee it worked.
            assert!(be_txn.commit().is_ok());
            r
        }};
    }

    macro_rules! entry_exists {
        ($be:expr, $ent:expr) => {{
            let ei = unsafe { $ent.clone().into_sealed_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![AttrString::from("uuid")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            let lims = Limits::unlimited();
            let entries = $be.search(&lims, &filt).expect("failed to search");
            entries.first().is_some()
        }};
    }

    macro_rules! entry_attr_pres {
        ($be:expr, $ent:expr, $attr:expr) => {{
            let ei = unsafe { $ent.clone().into_sealed_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![AttrString::from("userid")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            let lims = Limits::unlimited();
            let entries = $be.search(&lims, &filt).expect("failed to search");
            match entries.first() {
                Some(ent) => ent.attribute_pres($attr),
                None => false,
            }
        }};
    }

    macro_rules! idl_state {
        ($be:expr, $attr:expr, $itype:expr, $idx_key:expr, $expect:expr) => {{
            let t_idl = $be
                .load_test_idl(&$attr.to_string(), $itype, &$idx_key.to_string())
                .expect("IdList Load failed");
            let t = $expect.map(|v: Vec<u64>| IDLBitRange::from_iter(v));
            assert_eq!(t_idl, t);
        }};
    }

    #[test]
    fn test_be_simple_create() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Create");

            let empty_result = be.create(&CID_ZERO, Vec::new());
            trace!("{:?}", empty_result);
            assert_eq!(empty_result, Err(OperationError::EmptyRequest));

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e = unsafe { e.into_sealed_new() };

            let single_result = be.create(&CID_ZERO, vec![e.clone()]);

            assert!(single_result.is_ok());

            // Construct a filter
            assert!(entry_exists!(be, e));
        });
    }

    #[test]
    fn test_be_simple_search() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Search");

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("claire"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e = unsafe { e.into_sealed_new() };

            let single_result = be.create(&CID_ZERO, vec![e]);
            assert!(single_result.is_ok());
            // Test a simple EQ search

            let filt =
                unsafe { filter_resolved!(f_eq("userid", PartialValue::new_utf8s("claire"))) };

            let lims = Limits::unlimited();

            let r = be.search(&lims, &filt);
            assert!(r.expect("Search failed!").len() == 1);

            // Test empty search

            // Test class pres

            // Search with no results
        });
    }

    #[test]
    fn test_be_simple_modify() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Modify");
            let lims = Limits::unlimited();
            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", Value::from("alice"));
            e2.add_ava("uuid", Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };

            assert!(be.create(&CID_ZERO, vec![ve1, ve2]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(&lims, unsafe { &filter_resolved!(f_pres("userid")) })
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);

            let mut r1 = unsafe { r1.as_ref().clone().into_invalid() };
            let mut r2 = unsafe { r2.as_ref().clone().into_invalid() };

            // Modify no id (err)
            // This is now impossible due to the state machine design.
            // However, with some unsafe ....
            let ue1 = unsafe { e1.clone().into_sealed_committed() };
            assert!(be
                .modify(&CID_ZERO, &[Arc::new(ue1.clone())], &[ue1])
                .is_err());
            // Modify none
            assert!(be.modify(&CID_ZERO, &[], &[]).is_err());

            // Make some changes to r1, r2.
            let pre1 = unsafe { Arc::new(r1.clone().into_sealed_committed()) };
            let pre2 = unsafe { Arc::new(r2.clone().into_sealed_committed()) };
            r1.add_ava("desc", Value::from("modified"));
            r2.add_ava("desc", Value::from("modified"));

            // Now ... cheat.

            let vr1 = unsafe { r1.into_sealed_committed() };
            let vr2 = unsafe { r2.into_sealed_committed() };

            // Modify single
            assert!(be.modify(&CID_ZERO, &[pre1], &[vr1.clone()]).is_ok());
            // Assert no other changes
            assert!(entry_attr_pres!(be, vr1, "desc"));
            assert!(!entry_attr_pres!(be, vr2, "desc"));

            // Modify both
            assert!(be
                .modify(
                    &CID_ZERO,
                    &[Arc::new(vr1.clone()), pre2],
                    &[vr1.clone(), vr2.clone()]
                )
                .is_ok());

            assert!(entry_attr_pres!(be, vr1, "desc"));
            assert!(entry_attr_pres!(be, vr2, "desc"));
        });
    }

    #[test]
    fn test_be_simple_delete() {
        run_test!(|be: &mut BackendWriteTransaction| {
            trace!("Simple Delete");
            let lims = Limits::unlimited();

            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", Value::from("alice"));
            e2.add_ava("uuid", Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", Value::from("lucy"));
            e3.add_ava("uuid", Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };
            let ve3 = unsafe { e3.clone().into_sealed_new() };

            assert!(be.create(&CID_ZERO, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));
            assert!(entry_exists!(be, e3));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(&lims, unsafe { &filter_resolved!(f_pres("userid")) })
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);
            let r3 = results.remove(0);

            // Deletes nothing, all entries are live.
            assert!(matches!(be.reap_tombstones(&CID_ZERO), Ok(0)));

            // Put them into the tombstone state, and write that down.
            // This sets up the RUV with the changes.
            let r1_ts = unsafe { r1.to_tombstone(CID_ONE.clone()).into_sealed_committed() };

            assert!(be.modify(&CID_ONE, &[r1], &[r1_ts.clone()]).is_ok());

            let r2_ts = unsafe { r2.to_tombstone(CID_TWO.clone()).into_sealed_committed() };
            let r3_ts = unsafe { r3.to_tombstone(CID_TWO.clone()).into_sealed_committed() };

            assert!(be
                .modify(&CID_TWO, &[r2, r3], &[r2_ts.clone(), r3_ts.clone()])
                .is_ok());

            // The entry are now tombstones, but is still in the ruv. This is because we
            // targeted CID_ZERO, not ONE.
            assert!(matches!(be.reap_tombstones(&CID_ZERO), Ok(0)));

            assert!(entry_exists!(be, r1_ts));
            assert!(entry_exists!(be, r2_ts));
            assert!(entry_exists!(be, r3_ts));

            assert!(matches!(be.reap_tombstones(&CID_ONE), Ok(0)));

            assert!(entry_exists!(be, r1_ts));
            assert!(entry_exists!(be, r2_ts));
            assert!(entry_exists!(be, r3_ts));

            assert!(matches!(be.reap_tombstones(&CID_TWO), Ok(1)));

            assert!(!entry_exists!(be, r1_ts));
            assert!(entry_exists!(be, r2_ts));
            assert!(entry_exists!(be, r3_ts));

            assert!(matches!(be.reap_tombstones(&CID_THREE), Ok(2)));

            assert!(!entry_exists!(be, r1_ts));
            assert!(!entry_exists!(be, r2_ts));
            assert!(!entry_exists!(be, r3_ts));

            // Nothing left
            assert!(matches!(be.reap_tombstones(&CID_THREE), Ok(0)));

            assert!(!entry_exists!(be, r1_ts));
            assert!(!entry_exists!(be, r2_ts));
            assert!(!entry_exists!(be, r3_ts));
        });
    }

    #[test]
    fn test_be_backup_restore() {
        let db_backup_file_name = format!(
            "{}/.backup_test.json",
            option_env!("OUT_DIR").unwrap_or("/tmp")
        );
        eprintln!(" ⚠️   {}", db_backup_file_name);
        run_test!(|be: &mut BackendWriteTransaction| {
            // Important! Need db metadata setup!
            be.reset_db_s_uuid().unwrap();
            be.reset_db_d_uuid().unwrap();
            be.set_db_ts_max(Duration::from_secs(1)).unwrap();

            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", Value::from("alice"));
            e2.add_ava("uuid", Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", Value::from("lucy"));
            e3.add_ava("uuid", Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };
            let ve3 = unsafe { e3.clone().into_sealed_new() };

            assert!(be.create(&CID_ZERO, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));
            assert!(entry_exists!(be, e3));

            let result = fs::remove_file(&db_backup_file_name);

            match result {
                Err(e) => {
                    // if the error is the file is not found, that's what we want so continue,
                    // otherwise return the error
                    match e.kind() {
                        std::io::ErrorKind::NotFound => {}
                        _ => (),
                    }
                }
                _ => (),
            }

            be.backup(&db_backup_file_name).expect("Backup failed!");
            be.restore(&db_backup_file_name).expect("Restore failed!");

            assert!(be.verify().is_empty());
        });
    }

    #[test]
    fn test_be_backup_restore_tampered() {
        let db_backup_file_name = format!(
            "{}/.backup2_test.json",
            option_env!("OUT_DIR").unwrap_or("/tmp")
        );
        eprintln!(" ⚠️   {}", db_backup_file_name);
        run_test!(|be: &mut BackendWriteTransaction| {
            // Important! Need db metadata setup!
            be.reset_db_s_uuid().unwrap();
            be.reset_db_d_uuid().unwrap();
            be.set_db_ts_max(Duration::from_secs(1)).unwrap();
            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", Value::from("alice"));
            e2.add_ava("uuid", Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", Value::from("lucy"));
            e3.add_ava("uuid", Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };
            let ve3 = unsafe { e3.clone().into_sealed_new() };

            assert!(be.create(&CID_ZERO, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(be, e1));
            assert!(entry_exists!(be, e2));
            assert!(entry_exists!(be, e3));

            let result = fs::remove_file(&db_backup_file_name);

            match result {
                Err(e) => {
                    // if the error is the file is not found, that's what we want so continue,
                    // otherwise return the error
                    match e.kind() {
                        std::io::ErrorKind::NotFound => {}
                        _ => (),
                    }
                }
                _ => (),
            }

            be.backup(&db_backup_file_name).expect("Backup failed!");

            // Now here, we need to tamper with the file.
            let serialized_string = fs::read_to_string(&db_backup_file_name).unwrap();
            let mut dbbak: DbBackup = serde_json::from_str(&serialized_string).unwrap();

            match &mut dbbak {
                DbBackup::V1(_) => {
                    // We no longer use these format versions!
                    unreachable!()
                }
                DbBackup::V2 {
                    db_s_uuid: _,
                    db_d_uuid: _,
                    db_ts_max: _,
                    entries,
                } => {
                    let _ = entries.pop();
                }
            };

            let serialized_entries_str = serde_json::to_string_pretty(&dbbak).unwrap();
            fs::write(&db_backup_file_name, serialized_entries_str).unwrap();

            be.restore(&db_backup_file_name).expect("Restore failed!");

            assert!(be.verify().is_empty());
        });
    }

    #[test]
    fn test_be_sid_generation_and_reset() {
        run_test!(|be: &mut BackendWriteTransaction| {
            let sid1 = be.get_db_s_uuid();
            let sid2 = be.get_db_s_uuid();
            assert!(sid1 == sid2);
            let sid3 = be.reset_db_s_uuid().unwrap();
            assert!(sid1 != sid3);
            let sid4 = be.get_db_s_uuid();
            assert!(sid3 == sid4);
        });
    }

    #[test]
    fn test_be_reindex_empty() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Add some test data?
            let missing = be.missing_idxs().unwrap();
            assert!(missing.len() == 7);
            assert!(be.reindex().is_ok());
            let missing = be.missing_idxs().unwrap();
            debug!("{:?}", missing);
            assert!(missing.is_empty());
        });
    }

    #[test]
    fn test_be_reindex_data() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Add some test data?
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::new_iname("claire"));
            e2.add_ava("uuid", Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"));
            let e2 = unsafe { e2.into_sealed_new() };

            be.create(&CID_ZERO, vec![e1, e2]).unwrap();

            // purge indexes
            be.purge_idxs().unwrap();
            // Check they are gone
            let missing = be.missing_idxs().unwrap();
            assert!(missing.len() == 7);
            assert!(be.reindex().is_ok());
            let missing = be.missing_idxs().unwrap();
            debug!("{:?}", missing);
            assert!(missing.is_empty());
            // check name and uuid ids on eq, sub, pres

            idl_state!(be, "name", IndexType::Equality, "william", Some(vec![1]));

            idl_state!(be, "name", IndexType::Equality, "claire", Some(vec![2]));

            idl_state!(be, "name", IndexType::Presence, "_", Some(vec![1, 2]));

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(vec![1])
            );

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "bd651620-00dd-426b-aaa0-4494f7b7906f",
                Some(vec![2])
            );

            idl_state!(be, "uuid", IndexType::Presence, "_", Some(vec![1, 2]));

            // Show what happens with empty

            idl_state!(
                be,
                "name",
                IndexType::Equality,
                "not-exist",
                Some(Vec::new())
            );

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "fake-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::new())
            );

            let uuid_p_idl = be
                .load_test_idl(
                    &"not_indexed".to_string(),
                    IndexType::Presence,
                    &"_".to_string(),
                )
                .unwrap(); // unwrap the result
            assert_eq!(uuid_p_idl, None);

            // Check name2uuid
            let claire_uuid = uuid!("bd651620-00dd-426b-aaa0-4494f7b7906f");
            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");

            assert!(be.name2uuid("claire") == Ok(Some(claire_uuid)));
            assert!(be.name2uuid("william") == Ok(Some(william_uuid)));
            assert!(be.name2uuid("db237e8a-0079-4b8c-8a56-593b22aa44d1") == Ok(None));
            // check uuid2spn
            assert!(be.uuid2spn(claire_uuid) == Ok(Some(Value::new_iname("claire"))));
            assert!(be.uuid2spn(william_uuid) == Ok(Some(Value::new_iname("william"))));
            // check uuid2rdn
            assert!(be.uuid2rdn(claire_uuid) == Ok(Some("name=claire".to_string())));
            assert!(be.uuid2rdn(william_uuid) == Ok(Some("name=william".to_string())));
        });
    }

    #[test]
    fn test_be_index_create_delete_simple() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // First, setup our index tables!
            assert!(be.reindex().is_ok());
            // Test that on entry create, the indexes are made correctly.
            // this is a similar case to reindex.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(&CID_ZERO, vec![e1]).unwrap();
            let mut rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            let e1 = rset.pop().unwrap();

            idl_state!(be, "name", IndexType::Equality, "william", Some(vec![1]));

            idl_state!(be, "name", IndexType::Presence, "_", Some(vec![1]));

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(vec![1])
            );

            idl_state!(be, "uuid", IndexType::Presence, "_", Some(vec![1]));

            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            assert!(be.name2uuid("william") == Ok(Some(william_uuid)));
            assert!(be.uuid2spn(william_uuid) == Ok(Some(Value::from("william"))));
            assert!(be.uuid2rdn(william_uuid) == Ok(Some("name=william".to_string())));

            // == Now we reap_tombstones, and assert we removed the items.
            let e1_ts = unsafe { e1.to_tombstone(CID_ONE.clone()).into_sealed_committed() };
            assert!(be.modify(&CID_ONE, &[e1], &[e1_ts]).is_ok());
            be.reap_tombstones(&CID_TWO).unwrap();

            idl_state!(be, "name", IndexType::Equality, "william", Some(Vec::new()));

            idl_state!(be, "name", IndexType::Presence, "_", Some(Vec::new()));

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::new())
            );

            idl_state!(be, "uuid", IndexType::Presence, "_", Some(Vec::new()));

            assert!(be.name2uuid("william") == Ok(None));
            assert!(be.uuid2spn(william_uuid) == Ok(None));
            assert!(be.uuid2rdn(william_uuid) == Ok(None));
        })
    }

    #[test]
    fn test_be_index_create_delete_multi() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // delete multiple entries at a time, without deleting others
            // First, setup our index tables!
            assert!(be.reindex().is_ok());
            // Test that on entry create, the indexes are made correctly.
            // this is a similar case to reindex.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::new_iname("claire"));
            e2.add_ava("uuid", Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"));
            let e2 = unsafe { e2.into_sealed_new() };

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", Value::new_iname("lucy"));
            e3.add_ava("uuid", Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));
            let e3 = unsafe { e3.into_sealed_new() };

            let mut rset = be.create(&CID_ZERO, vec![e1, e2, e3]).unwrap();
            rset.remove(1);
            let mut rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            let e1 = rset.pop().unwrap();
            let e3 = rset.pop().unwrap();

            // Now remove e1, e3.
            let e1_ts = unsafe { e1.to_tombstone(CID_ONE.clone()).into_sealed_committed() };
            let e3_ts = unsafe { e3.to_tombstone(CID_ONE.clone()).into_sealed_committed() };
            assert!(be.modify(&CID_ONE, &[e1, e3], &[e1_ts, e3_ts]).is_ok());
            be.reap_tombstones(&CID_TWO).unwrap();

            idl_state!(be, "name", IndexType::Equality, "claire", Some(vec![2]));

            idl_state!(be, "name", IndexType::Presence, "_", Some(vec![2]));

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "bd651620-00dd-426b-aaa0-4494f7b7906f",
                Some(vec![2])
            );

            idl_state!(be, "uuid", IndexType::Presence, "_", Some(vec![2]));

            let claire_uuid = uuid!("bd651620-00dd-426b-aaa0-4494f7b7906f");
            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            let lucy_uuid = uuid!("7b23c99d-c06b-4a9a-a958-3afa56383e1d");

            assert!(be.name2uuid("claire") == Ok(Some(claire_uuid)));
            let x = be.uuid2spn(claire_uuid);
            trace!(?x);
            assert!(be.uuid2spn(claire_uuid) == Ok(Some(Value::new_iname("claire"))));
            assert!(be.uuid2rdn(claire_uuid) == Ok(Some("name=claire".to_string())));

            assert!(be.name2uuid("william") == Ok(None));
            assert!(be.uuid2spn(william_uuid) == Ok(None));
            assert!(be.uuid2rdn(william_uuid) == Ok(None));

            assert!(be.name2uuid("lucy") == Ok(None));
            assert!(be.uuid2spn(lucy_uuid) == Ok(None));
            assert!(be.uuid2rdn(lucy_uuid) == Ok(None));
        })
    }

    #[test]
    fn test_be_index_modify_simple() {
        run_test!(|be: &mut BackendWriteTransaction| {
            assert!(be.reindex().is_ok());
            // modify with one type, ensuring we clean the indexes behind
            // us. For the test to be "accurate" we must add one attr, remove one attr
            // and change one attr.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("ta", Value::from("test"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(&CID_ZERO, vec![e1]).unwrap();
            let rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            // Now, alter the new entry.
            let mut ce1 = unsafe { rset[0].as_ref().clone().into_invalid() };
            // add something.
            ce1.add_ava("tb", Value::from("test"));
            // remove something.
            ce1.purge_ava("ta");
            // mod something.
            ce1.purge_ava("name");
            ce1.add_ava("name", Value::new_iname("claire"));

            let ce1 = unsafe { ce1.into_sealed_committed() };

            be.modify(&CID_ZERO, &rset, &[ce1]).unwrap();

            // Now check the idls
            idl_state!(be, "name", IndexType::Equality, "claire", Some(vec![1]));

            idl_state!(be, "name", IndexType::Presence, "_", Some(vec![1]));

            idl_state!(be, "tb", IndexType::Equality, "test", Some(vec![1]));

            idl_state!(be, "ta", IndexType::Equality, "test", Some(vec![]));

            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            assert!(be.name2uuid("william") == Ok(None));
            assert!(be.name2uuid("claire") == Ok(Some(william_uuid)));
            assert!(be.uuid2spn(william_uuid) == Ok(Some(Value::new_iname("claire"))));
            assert!(be.uuid2rdn(william_uuid) == Ok(Some("name=claire".to_string())));
        })
    }

    #[test]
    fn test_be_index_modify_rename() {
        run_test!(|be: &mut BackendWriteTransaction| {
            assert!(be.reindex().is_ok());
            // test when we change name AND uuid
            // This will be needing to be correct for conflicts when we add
            // replication support!
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(&CID_ZERO, vec![e1]).unwrap();
            let rset: Vec<_> = rset.into_iter().map(Arc::new).collect();
            // Now, alter the new entry.
            let mut ce1 = unsafe { rset[0].as_ref().clone().into_invalid() };
            ce1.purge_ava("name");
            ce1.purge_ava("uuid");
            ce1.add_ava("name", Value::new_iname("claire"));
            ce1.add_ava("uuid", Value::from("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8"));
            let ce1 = unsafe { ce1.into_sealed_committed() };

            be.modify(&CID_ZERO, &rset, &[ce1]).unwrap();

            idl_state!(be, "name", IndexType::Equality, "claire", Some(vec![1]));

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "04091a7a-6ce4-42d2-abf5-c2ce244ac9e8",
                Some(vec![1])
            );

            idl_state!(be, "name", IndexType::Presence, "_", Some(vec![1]));
            idl_state!(be, "uuid", IndexType::Presence, "_", Some(vec![1]));

            idl_state!(
                be,
                "uuid",
                IndexType::Equality,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::new())
            );
            idl_state!(be, "name", IndexType::Equality, "william", Some(Vec::new()));

            let claire_uuid = uuid!("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8");
            let william_uuid = uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1");
            assert!(be.name2uuid("william") == Ok(None));
            assert!(be.name2uuid("claire") == Ok(Some(claire_uuid)));
            assert!(be.uuid2spn(william_uuid) == Ok(None));
            assert!(be.uuid2rdn(william_uuid) == Ok(None));
            assert!(be.uuid2spn(claire_uuid) == Ok(Some(Value::new_iname("claire"))));
            assert!(be.uuid2rdn(claire_uuid) == Ok(Some("name=claire".to_string())));
        })
    }

    #[test]
    fn test_be_index_search_simple() {
        run_test!(|be: &mut BackendWriteTransaction| {
            assert!(be.reindex().is_ok());

            // Create a test entry with some indexed / unindexed values.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("no-index", Value::from("william"));
            e1.add_ava("other-no-index", Value::from("william"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::new_iname("claire"));
            e2.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d2"));
            let e2 = unsafe { e2.into_sealed_new() };

            let _rset = be.create(&CID_ZERO, vec![e1, e2]).unwrap();
            // Test fully unindexed
            let f_un =
                unsafe { filter_resolved!(f_eq("no-index", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(f_un.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            // Test that a fully indexed search works
            let feq = unsafe { filter_resolved!(f_eq("name", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(feq.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            // Test and/or
            //   full index and
            let f_in_and = unsafe {
                filter_resolved!(f_and!([
                    f_eq("name", PartialValue::new_utf8s("william")),
                    f_eq(
                        "uuid",
                        PartialValue::new_utf8s("db237e8a-0079-4b8c-8a56-593b22aa44d1")
                    )
                ]))
            };

            let (r, _plan) = be.filter2idl(f_in_and.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            //   partial index and
            let f_p1 = unsafe {
                filter_resolved!(f_and!([
                    f_eq("name", PartialValue::new_utf8s("william")),
                    f_eq("no-index", PartialValue::new_utf8s("william"))
                ]))
            };

            let f_p2 = unsafe {
                filter_resolved!(f_and!([
                    f_eq("name", PartialValue::new_utf8s("william")),
                    f_eq("no-index", PartialValue::new_utf8s("william"))
                ]))
            };

            let (r, _plan) = be.filter2idl(f_p1.to_inner(), 0).unwrap();
            match r {
                IdList::Partial(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            let (r, _plan) = be.filter2idl(f_p2.to_inner(), 0).unwrap();
            match r {
                IdList::Partial(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            //   no index and
            let f_no_and = unsafe {
                filter_resolved!(f_and!([
                    f_eq("no-index", PartialValue::new_utf8s("william")),
                    f_eq("other-no-index", PartialValue::new_utf8s("william"))
                ]))
            };

            let (r, _plan) = be.filter2idl(f_no_and.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            //   full index or
            let f_in_or = unsafe {
                filter_resolved!(f_or!([f_eq("name", PartialValue::new_utf8s("william"))]))
            };

            let (r, _plan) = be.filter2idl(f_in_or.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }
            //   partial (aka allids) or
            let f_un_or = unsafe {
                filter_resolved!(f_or!([f_eq(
                    "no-index",
                    PartialValue::new_utf8s("william")
                )]))
            };

            let (r, _plan) = be.filter2idl(f_un_or.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            // Test root andnot
            let f_r_andnot = unsafe {
                filter_resolved!(f_andnot(f_eq("name", PartialValue::new_utf8s("william"))))
            };

            let (r, _plan) = be.filter2idl(f_r_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(Vec::new()));
                }
                _ => {
                    panic!("");
                }
            }

            // test andnot as only in and
            let f_and_andnot = unsafe {
                filter_resolved!(f_and!([f_andnot(f_eq(
                    "name",
                    PartialValue::new_utf8s("william")
                ))]))
            };

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(Vec::new()));
                }
                _ => {
                    panic!("");
                }
            }
            // test andnot as only in or
            let f_or_andnot = unsafe {
                filter_resolved!(f_or!([f_andnot(f_eq(
                    "name",
                    PartialValue::new_utf8s("william")
                ))]))
            };

            let (r, _plan) = be.filter2idl(f_or_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(Vec::new()));
                }
                _ => {
                    panic!("");
                }
            }

            // test andnot in and (first) with name
            let f_and_andnot = unsafe {
                filter_resolved!(f_and!([
                    f_andnot(f_eq("name", PartialValue::new_utf8s("claire"))),
                    f_pres("name")
                ]))
            };

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    debug!("{:?}", idl);
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }
            // test andnot in and (last) with name
            let f_and_andnot = unsafe {
                filter_resolved!(f_and!([
                    f_pres("name"),
                    f_andnot(f_eq("name", PartialValue::new_utf8s("claire")))
                ]))
            };

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }
            // test andnot in and (first) with no-index
            let f_and_andnot = unsafe {
                filter_resolved!(f_and!([
                    f_andnot(f_eq("name", PartialValue::new_utf8s("claire"))),
                    f_pres("no-index")
                ]))
            };

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }
            // test andnot in and (last) with no-index
            let f_and_andnot = unsafe {
                filter_resolved!(f_and!([
                    f_pres("no-index"),
                    f_andnot(f_eq("name", PartialValue::new_utf8s("claire")))
                ]))
            };

            let (r, _plan) = be.filter2idl(f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }

            //   empty or
            let f_e_or = unsafe { filter_resolved!(f_or!([])) };

            let (r, _plan) = be.filter2idl(f_e_or.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![]));
                }
                _ => {
                    panic!("");
                }
            }

            let f_e_and = unsafe { filter_resolved!(f_and!([])) };

            let (r, _plan) = be.filter2idl(f_e_and.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![]));
                }
                _ => {
                    panic!("");
                }
            }
        })
    }

    #[test]
    fn test_be_index_search_missing() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Test where the index is in schema but not created (purge idxs)
            // should fall back to an empty set because we can't satisfy the term
            be.purge_idxs().unwrap();
            debug!("{:?}", be.missing_idxs().unwrap());
            let f_eq =
                unsafe { filter_resolved!(f_eq("name", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(f_eq.to_inner(), 0).unwrap();
            match r {
                IdList::AllIds => {}
                _ => {
                    panic!("");
                }
            }
        })
    }

    #[test]
    fn test_be_index_slope_generation() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // Create some test entry with some indexed / unindexed values.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("ta", Value::from("dupe"));
            e1.add_ava("tb", Value::from("1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::new_iname("claire"));
            e2.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d2"));
            e2.add_ava("ta", Value::from("dupe"));
            e2.add_ava("tb", Value::from("1"));
            let e2 = unsafe { e2.into_sealed_new() };

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("name", Value::new_iname("benny"));
            e3.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d3"));
            e3.add_ava("ta", Value::from("dupe"));
            e3.add_ava("tb", Value::from("2"));
            let e3 = unsafe { e3.into_sealed_new() };

            let _rset = be.create(&CID_ZERO, vec![e1, e2, e3]).unwrap();

            // If the slopes haven't been generated yet, there are some hardcoded values
            // that we can use instead. They aren't generated until a first re-index.
            assert!(!be.is_idx_slopeyness_generated().unwrap());

            let ta_eq_slope = be
                .get_idx_slope(&IdxKey::new("ta", IndexType::Equality))
                .unwrap();
            assert_eq!(ta_eq_slope, 45);

            let tb_eq_slope = be
                .get_idx_slope(&IdxKey::new("tb", IndexType::Equality))
                .unwrap();
            assert_eq!(tb_eq_slope, 45);

            let name_eq_slope = be
                .get_idx_slope(&IdxKey::new("name", IndexType::Equality))
                .unwrap();
            assert_eq!(name_eq_slope, 1);
            let uuid_eq_slope = be
                .get_idx_slope(&IdxKey::new("uuid", IndexType::Equality))
                .unwrap();
            assert_eq!(uuid_eq_slope, 1);

            let name_pres_slope = be
                .get_idx_slope(&IdxKey::new("name", IndexType::Presence))
                .unwrap();
            assert_eq!(name_pres_slope, 90);
            let uuid_pres_slope = be
                .get_idx_slope(&IdxKey::new("uuid", IndexType::Presence))
                .unwrap();
            assert_eq!(uuid_pres_slope, 90);
            // Check the slopes are what we expect for hardcoded values.

            // Now check slope generation for the values. Today these are calculated
            // at reindex time, so we now perform the re-index.
            assert!(be.reindex().is_ok());
            assert!(be.is_idx_slopeyness_generated().unwrap());

            let ta_eq_slope = be
                .get_idx_slope(&IdxKey::new("ta", IndexType::Equality))
                .unwrap();
            assert_eq!(ta_eq_slope, 200);

            let tb_eq_slope = be
                .get_idx_slope(&IdxKey::new("tb", IndexType::Equality))
                .unwrap();
            assert_eq!(tb_eq_slope, 133);

            let name_eq_slope = be
                .get_idx_slope(&IdxKey::new("name", IndexType::Equality))
                .unwrap();
            assert_eq!(name_eq_slope, 51);
            let uuid_eq_slope = be
                .get_idx_slope(&IdxKey::new("uuid", IndexType::Equality))
                .unwrap();
            assert_eq!(uuid_eq_slope, 51);

            let name_pres_slope = be
                .get_idx_slope(&IdxKey::new("name", IndexType::Presence))
                .unwrap();
            assert_eq!(name_pres_slope, 200);
            let uuid_pres_slope = be
                .get_idx_slope(&IdxKey::new("uuid", IndexType::Presence))
                .unwrap();
            assert_eq!(uuid_pres_slope, 200);
        })
    }

    #[test]
    fn test_be_limits_allids() {
        run_test!(|be: &mut BackendWriteTransaction| {
            let mut lim_allow_allids = Limits::unlimited();
            lim_allow_allids.unindexed_allow = true;

            let mut lim_deny_allids = Limits::unlimited();
            lim_deny_allids.unindexed_allow = false;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e.add_ava("nonexist", Value::from("x"));
            let e = unsafe { e.into_sealed_new() };
            let single_result = be.create(&CID_ZERO, vec![e.clone()]);

            assert!(single_result.is_ok());
            let filt = unsafe {
                e.filter_from_attrs(&[AttrString::from("nonexist")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            // check allow on allids
            let res = be.search(&lim_allow_allids, &filt);
            assert!(res.is_ok());
            let res = be.exists(&lim_allow_allids, &filt);
            assert!(res.is_ok());

            // check deny on allids
            let res = be.search(&lim_deny_allids, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            let res = be.exists(&lim_deny_allids, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
        })
    }

    #[test]
    fn test_be_limits_results_max() {
        run_test!(|be: &mut BackendWriteTransaction| {
            let mut lim_allow = Limits::unlimited();
            lim_allow.search_max_results = usize::MAX;

            let mut lim_deny = Limits::unlimited();
            lim_deny.search_max_results = 0;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e.add_ava("nonexist", Value::from("x"));
            let e = unsafe { e.into_sealed_new() };
            let single_result = be.create(&CID_ZERO, vec![e.clone()]);
            assert!(single_result.is_ok());

            let filt = unsafe {
                e.filter_from_attrs(&[AttrString::from("nonexist")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };

            // --> This is the all ids path (unindexed)
            // check allow on entry max
            let res = be.search(&lim_allow, &filt);
            assert!(res.is_ok());
            let res = be.exists(&lim_allow, &filt);
            assert!(res.is_ok());

            // check deny on entry max
            let res = be.search(&lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(&lim_deny, &filt);
            assert!(res.is_ok());

            // --> This will shortcut due to indexing.
            assert!(be.reindex().is_ok());
            let res = be.search(&lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(&lim_deny, &filt);
            assert!(res.is_ok());
        })
    }

    #[test]
    fn test_be_limits_partial_filter() {
        run_test!(|be: &mut BackendWriteTransaction| {
            // This relies on how we do partials, so it could be a bit sensitive.
            // A partial is generated after an allids + indexed in a single and
            // as we require both conditions to exist. Allids comes from unindexed
            // terms. we need to ensure we don't hit partial threshold too.
            //
            // This means we need an and query where the first term is allids
            // and the second is indexed, but without the filter shortcutting.
            //
            // To achieve this we need a monstrously evil query.
            //
            let mut lim_allow = Limits::unlimited();
            lim_allow.search_max_filter_test = usize::MAX;

            let mut lim_deny = Limits::unlimited();
            lim_deny.search_max_filter_test = 0;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("name", Value::new_iname("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e.add_ava("nonexist", Value::from("x"));
            e.add_ava("nonexist", Value::from("y"));
            let e = unsafe { e.into_sealed_new() };
            let single_result = be.create(&CID_ZERO, vec![e]);
            assert!(single_result.is_ok());

            // Reindex so we have things in place for our query
            assert!(be.reindex().is_ok());

            // 🚨 This is evil!
            // The and allows us to hit "allids + indexed -> partial".
            // the or terms prevent re-arrangement. They can't be folded or dead
            // term elimed either.
            //
            // This means the f_or nonexist will become allids and the second will be indexed
            // due to f_eq userid in both with the result of william.
            //
            // This creates a partial, and because it's the first iteration in the loop, this
            // doesn't encounter partial threshold testing.
            let filt = unsafe {
                filter_resolved!(f_and!([
                    f_or!([
                        f_eq("nonexist", PartialValue::new_utf8s("x")),
                        f_eq("nonexist", PartialValue::new_utf8s("y"))
                    ]),
                    f_or!([
                        f_eq("name", PartialValue::new_utf8s("claire")),
                        f_eq("name", PartialValue::new_utf8s("william"))
                    ]),
                ]))
            };

            let res = be.search(&lim_allow, &filt);
            assert!(res.is_ok());
            let res = be.exists(&lim_allow, &filt);
            assert!(res.is_ok());

            // check deny on entry max
            let res = be.search(&lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(&lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
        })
    }

    #[test]
    fn test_be_mulitple_create() {
        sketching::test_init();

        // This is a demo idxmeta, purely for testing.
        let idxmeta = vec![IdxKey {
            attr: AttrString::from("uuid"),
            itype: IndexType::Equality,
        }];

        let be_a = Backend::new(BackendConfig::new_test("main"), idxmeta.clone(), false)
            .expect("Failed to setup backend");

        let be_b = Backend::new(BackendConfig::new_test("db_2"), idxmeta, false)
            .expect("Failed to setup backend");

        let mut be_a_txn = be_a.write();
        let mut be_b_txn = be_b.write();

        assert!(be_a_txn.get_db_s_uuid() != be_b_txn.get_db_s_uuid());

        // Create into A
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava("userid", Value::from("william"));
        e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
        let e = unsafe { e.into_sealed_new() };

        let single_result = be_a_txn.create(&CID_ZERO, vec![e]);

        assert!(single_result.is_ok());

        // Assert it's in A but not B.
        let filt = unsafe { filter_resolved!(f_eq("userid", PartialValue::new_utf8s("william"))) };

        let lims = Limits::unlimited();

        let r = be_a_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").len() == 1);

        let r = be_b_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").is_empty());

        // Create into B
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava("userid", Value::from("claire"));
        e.add_ava("uuid", Value::from("0c680959-0944-47d6-9dea-53304d124266"));
        let e = unsafe { e.into_sealed_new() };

        let single_result = be_b_txn.create(&CID_ZERO, vec![e]);

        assert!(single_result.is_ok());

        // Assert it's in B but not A
        let filt = unsafe { filter_resolved!(f_eq("userid", PartialValue::new_utf8s("claire"))) };

        let lims = Limits::unlimited();

        let r = be_a_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").is_empty());

        let r = be_b_txn.search(&lims, &filt);
        assert!(r.expect("Search failed!").len() == 1);
    }
}
