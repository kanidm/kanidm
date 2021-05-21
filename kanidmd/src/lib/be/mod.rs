use std::fs;

use crate::value::IndexType;
use hashbrown::HashSet as Set;
use std::cell::UnsafeCell;
use std::sync::Arc;

use crate::audit::AuditScope;
use crate::be::dbentry::DbEntry;
use crate::entry::{Entry, EntryCommitted, EntryNew, EntrySealed};
use crate::event::EventLimits;
use crate::filter::{Filter, FilterPlan, FilterResolved, FilterValidResolved};
use crate::value::Value;
use concread::cowcell::*;
use idlset::v2::IDLBitRange;
use idlset::AndNot;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use smartstring::alias::String as AttrString;
use std::ops::DerefMut;
use std::time::Duration;
use uuid::Uuid;

pub mod dbentry;
pub mod dbvalue;
mod idl_arc_sqlite;
mod idl_sqlite;
pub(crate) mod idxkey;

pub(crate) use self::idxkey::{IdxKey, IdxKeyRef, IdxKeyToRef};

use crate::be::idl_arc_sqlite::{
    IdlArcSqlite, IdlArcSqliteReadTransaction, IdlArcSqliteTransaction,
    IdlArcSqliteWriteTransaction,
};

// Re-export this
pub use crate::be::idl_sqlite::FsType;

const FILTER_SEARCH_TEST_THRESHOLD: usize = 2;
const FILTER_EXISTS_TEST_THRESHOLD: usize = 0;

#[derive(Debug, Clone)]
pub enum IdList {
    ALLIDS,
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
    pub idxkeys: Set<IdxKey>,
}

impl IdxMeta {
    pub fn new(idxkeys: Set<IdxKey>) -> Self {
        IdxMeta { idxkeys }
    }
}

#[derive(Clone)]
pub struct BackendConfig {
    path: String,
    pool_size: u32,
    fstype: FsType,
    // Cachesizes?
    arcsize: Option<usize>,
}

impl BackendConfig {
    pub fn new(path: &str, pool_size: u32, fstype: FsType, arcsize: Option<usize>) -> Self {
        BackendConfig {
            pool_size,
            path: path.to_string(),
            fstype,
            arcsize,
        }
    }

    pub(crate) fn new_test() -> Self {
        BackendConfig {
            pool_size: 1,
            path: "".to_string(),
            fstype: FsType::Generic,
            arcsize: Some(1024),
        }
    }
}

#[derive(Clone)]
pub struct Backend {
    idlayer: Arc<IdlArcSqlite>,
    /// This is a copy-on-write cache of the index metadata that has been
    /// extracted from attributes set, in the correct format for the backend
    /// to consume.
    idxmeta: Arc<CowCell<IdxMeta>>,
    cfg: BackendConfig,
}

pub struct BackendReadTransaction<'a> {
    idlayer: UnsafeCell<IdlArcSqliteReadTransaction<'a>>,
    idxmeta: CowCellReadTxn<IdxMeta>,
}

pub struct BackendWriteTransaction<'a> {
    idlayer: UnsafeCell<IdlArcSqliteWriteTransaction<'a>>,
    idxmeta: CowCellReadTxn<IdxMeta>,
    idxmeta_wr: CowCellWriteTxn<'a, IdxMeta>,
}

impl IdRawEntry {
    fn into_entry(
        self,
        au: &mut AuditScope,
    ) -> Result<Entry<EntrySealed, EntryCommitted>, OperationError> {
        let db_e = serde_cbor::from_slice(self.data.as_slice())
            .map_err(|_| OperationError::SerdeCborError)?;
        // let id = u64::try_from(self.id).map_err(|_| OperationError::InvalidEntryId)?;
        Entry::from_dbentry(au, db_e, self.id).map_err(|_| OperationError::CorruptedEntry(self.id))
    }
}

pub trait BackendTransaction {
    type IdlLayerType: IdlArcSqliteTransaction;

    #[allow(clippy::mut_from_ref)]
    fn get_idlayer(&self) -> &mut Self::IdlLayerType;

    fn get_idxmeta_ref(&self) -> &IdxMeta;

    /// Recursively apply a filter, transforming into IdList's on the way. This builds a query
    /// execution log, so that it can be examined how an operation proceeded.
    #[allow(clippy::cognitive_complexity)]
    fn filter2idl(
        &self,
        au: &mut AuditScope,
        filt: &FilterResolved,
        thres: usize,
    ) -> Result<(IdList, FilterPlan), OperationError> {
        Ok(match filt {
            FilterResolved::Eq(attr, value, idx) => {
                if *idx {
                    // Get the idx_key
                    let idx_key = value.get_idx_eq_key();
                    // Get the idl for this
                    match self
                        .get_idlayer()
                        .get_idl(au, attr, &IndexType::EQUALITY, &idx_key)?
                    {
                        Some(idl) => (
                            IdList::Indexed(idl),
                            FilterPlan::EqIndexed(attr.clone(), idx_key),
                        ),
                        None => (IdList::ALLIDS, FilterPlan::EqCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::ALLIDS, FilterPlan::EqUnindexed(attr.clone()))
                }
            }
            FilterResolved::Sub(attr, subvalue, idx) => {
                if *idx {
                    // Get the idx_key
                    let idx_key = subvalue.get_idx_sub_key();
                    // Get the idl for this
                    match self
                        .get_idlayer()
                        .get_idl(au, attr, &IndexType::SUBSTRING, &idx_key)?
                    {
                        Some(idl) => (
                            IdList::Indexed(idl),
                            FilterPlan::SubIndexed(attr.clone(), idx_key),
                        ),
                        None => (IdList::ALLIDS, FilterPlan::SubCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::ALLIDS, FilterPlan::SubUnindexed(attr.clone()))
                }
            }
            FilterResolved::Pres(attr, idx) => {
                if *idx {
                    // Get the idl for this
                    match self.get_idlayer().get_idl(
                        au,
                        attr,
                        &IndexType::PRESENCE,
                        &"_".to_string(),
                    )? {
                        Some(idl) => (IdList::Indexed(idl), FilterPlan::PresIndexed(attr.clone())),
                        None => (IdList::ALLIDS, FilterPlan::PresCorrupt(attr.clone())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IdList::ALLIDS, FilterPlan::PresUnindexed(attr.clone()))
                }
            }
            FilterResolved::LessThan(attr, _subvalue, _idx) => {
                // We have no process for indexing this right now.
                (IdList::ALLIDS, FilterPlan::LessThanUnindexed(attr.clone()))
            }
            FilterResolved::Or(l) => {
                // Importantly if this has no inner elements, this returns
                // an empty list.
                let mut plan = Vec::new();
                let mut result = IDLBitRange::new();
                let mut partial = false;
                let mut threshold = false;
                // For each filter in l
                for f in l.iter() {
                    // get their idls
                    match self.filter2idl(au, f, thres)? {
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
                        (IdList::ALLIDS, fp) => {
                            plan.push(fp);
                            // If we find anything unindexed, the whole term is unindexed.
                            lfilter!(au, "Term {:?} is ALLIDS, shortcut return", f);
                            let setplan = FilterPlan::OrUnindexed(plan);
                            return Ok((IdList::ALLIDS, setplan));
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
            FilterResolved::And(l) => {
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
                    Some(f) => self.filter2idl(au, f, thres)?,
                    None => {
                        lfilter_error!(au, "WARNING: And filter was empty, or contains only AndNot, can not evaluate.");
                        return Ok((IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid));
                    }
                };

                // Setup the counter of terms we have left to evaluate.
                // This is used so that we shortcut return ONLY when we really do have
                // more terms remaining.
                let mut f_rem_count = f_rem.len() + f_andnot.len() - 1;

                // Setup the query plan tracker
                let mut plan = Vec::new();
                plan.push(fp);

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
                    IdList::ALLIDS => {}
                }

                // Now, for all remaining,
                for f in f_rem_iter {
                    f_rem_count -= 1;
                    let (inter, fp) = self.filter2idl(au, f, thres)?;
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
                        (IdList::Indexed(i), IdList::ALLIDS)
                        | (IdList::ALLIDS, IdList::Indexed(i))
                        | (IdList::Partial(i), IdList::ALLIDS)
                        | (IdList::ALLIDS, IdList::Partial(i)) => IdList::Partial(i),
                        (IdList::PartialThreshold(i), IdList::ALLIDS)
                        | (IdList::ALLIDS, IdList::PartialThreshold(i)) => {
                            IdList::PartialThreshold(i)
                        }
                        (IdList::ALLIDS, IdList::ALLIDS) => IdList::ALLIDS,
                    };
                }

                // debug!("partial cand set ==> {:?}", cand_idl);

                for f in f_andnot.iter() {
                    f_rem_count -= 1;
                    let f_in = match f {
                        FilterResolved::AndNot(f_in) => f_in,
                        _ => {
                            lfilter_error!(
                                au,
                                "Invalid server state, a cand filter leaked to andnot set!"
                            );
                            return Err(OperationError::InvalidState);
                        }
                    };
                    let (inter, fp) = self.filter2idl(au, f_in, thres)?;
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

                        (IdList::Indexed(_), IdList::ALLIDS)
                        | (IdList::ALLIDS, IdList::Indexed(_))
                        | (IdList::Partial(_), IdList::ALLIDS)
                        | (IdList::ALLIDS, IdList::Partial(_))
                        | (IdList::PartialThreshold(_), IdList::ALLIDS)
                        | (IdList::ALLIDS, IdList::PartialThreshold(_)) => {
                            // We could actually generate allids here
                            // and then try to reduce the and-not set, but
                            // for now we just return all ids.
                            IdList::ALLIDS
                        }
                        (IdList::ALLIDS, IdList::ALLIDS) => IdList::ALLIDS,
                    };
                }

                // What state is the final cand idl in?
                let setplan = match cand_idl {
                    IdList::Indexed(_) => FilterPlan::AndIndexed(plan),
                    IdList::Partial(_) | IdList::PartialThreshold(_) => {
                        FilterPlan::AndPartial(plan)
                    }
                    IdList::ALLIDS => FilterPlan::AndUnindexed(plan),
                };

                // Finally, return the result.
                // debug!("final cand set ==> {:?}", cand_idl);
                (cand_idl, setplan)
            } // end and
            FilterResolved::Inclusion(l) => {
                // For inclusion to be valid, every term must have *at least* one element present.
                // This really relies on indexing, and so it's internal only - generally only
                // for fully indexed existance queries, such as from refint.

                // This has a lot in common with an And and Or but not really quite either.
                let mut plan = Vec::new();
                let mut result = IDLBitRange::new();
                // For each filter in l
                for f in l.iter() {
                    // get their idls
                    match self.filter2idl(au, f, thres)? {
                        (IdList::Indexed(idl), fp) => {
                            plan.push(fp);
                            if idl.is_empty() {
                                // It's empty, so something is missing. Bail fast.
                                lfilter!(au, "Inclusion is unable to proceed - an empty (missing) item was found!");
                                let setplan = FilterPlan::InclusionIndexed(plan);
                                return Ok((IdList::Indexed(IDLBitRange::new()), setplan));
                            } else {
                                result = result | idl;
                            }
                        }
                        (_, fp) => {
                            plan.push(fp);
                            lfilter_error!(
                                au,
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
            FilterResolved::AndNot(_f) => {
                // get the idl for f
                // now do andnot?
                lfilter_error!(
                    au,
                    "ERROR: Requested a top level or isolated AndNot, returning empty"
                );
                (IdList::Indexed(IDLBitRange::new()), FilterPlan::Invalid)
            }
        })
    }

    fn search(
        &self,
        au: &mut AuditScope,
        erl: &EventLimits,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.
        lperf_trace_segment!(au, "be::search", || {
            /*
            // Do a final optimise of the filter
            lfilter!(au, "filter unoptimised form --> {:?}", filt);
            let filt =
                lperf_trace_segment!(au, "be::search<filt::optimise>", || { filt.optimise() });
            lfilter!(au, "filter optimised to --> {:?}", filt);
            */
            lfilter!(au, "filter optimised --> {:?}", filt);

            // Using the indexes, resolve the IdList here, or ALLIDS.
            // Also get if the filter was 100% resolved or not.
            let (idl, fplan) = lperf_trace_segment!(au, "be::search -> filter2idl", || {
                self.filter2idl(au, filt.to_inner(), FILTER_SEARCH_TEST_THRESHOLD)
            })?;

            lfilter_info!(au, "filter executed plan -> {:?}", fplan);

            // Based on the IdList we determine if limits are required at this point.
            match &idl {
                IdList::ALLIDS => {
                    if !erl.unindexed_allow {
                        ladmin_error!(au, "filter (search) is fully unindexed, and not allowed by resource limits");
                        return Err(OperationError::ResourceLimit);
                    }
                }
                IdList::Partial(idl_br) => {
                    // if idl_br.len() > erl.search_max_filter_test {
                    if !idl_br.below_threshold(erl.search_max_filter_test) {
                        ladmin_error!(au, "filter (search) is partial indexed and greater than search_max_filter_test allowed by resource limits");
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
                        ladmin_error!(au, "filter (search) is indexed and greater than search_max_results allowed by resource limits");
                        return Err(OperationError::ResourceLimit);
                    }
                }
            };

            let entries = self.get_idlayer().get_identry(au, &idl).map_err(|e| {
                ladmin_error!(au, "get_identry failed {:?}", e);
                e
            })?;

            let entries_filtered = match idl {
                IdList::ALLIDS => lperf_segment!(au, "be::search<entry::ftest::allids>", || {
                    entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(&filt))
                        .collect()
                }),
                IdList::Partial(_) => {
                    lperf_segment!(au, "be::search<entry::ftest::partial>", || {
                        entries
                            .into_iter()
                            .filter(|e| e.entry_match_no_index(&filt))
                            .collect()
                    })
                }
                IdList::PartialThreshold(_) => {
                    lperf_trace_segment!(au, "be::search<entry::ftest::thresh>", || {
                        entries
                            .into_iter()
                            .filter(|e| e.entry_match_no_index(&filt))
                            .collect()
                    })
                }
                // Since the index fully resolved, we can shortcut the filter test step here!
                IdList::Indexed(_) => {
                    lfilter!(au, "filter (search) was fully indexed 👏");
                    entries
                }
            };

            // If the idl was not indexed, apply the resource limit now. Avoid the needless match since the
            // if statement is quick.
            if entries_filtered.len() > erl.search_max_results {
                ladmin_error!(au, "filter (search) is resolved and greater than search_max_results allowed by resource limits");
                return Err(OperationError::ResourceLimit);
            }

            Ok(entries_filtered)
        })
    }

    /// Given a filter, assert some condition exists.
    /// Basically, this is a specialised case of search, where we don't need to
    /// load any candidates if they match. This is heavily used in uuid
    /// refint and attr uniqueness.
    fn exists(
        &self,
        au: &mut AuditScope,
        erl: &EventLimits,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<bool, OperationError> {
        lperf_trace_segment!(au, "be::exists", || {
            /*
            // Do a final optimise of the filter
            lfilter!(au, "filter unoptimised form --> {:?}", filt);
            let filt = filt.optimise();
            lfilter!(au, "filter optimised to --> {:?}", filt);
            */
            lfilter!(au, "filter optimised --> {:?}", filt);

            // Using the indexes, resolve the IdList here, or ALLIDS.
            // Also get if the filter was 100% resolved or not.
            let (idl, fplan) = lperf_trace_segment!(au, "be::exists -> filter2idl", || {
                self.filter2idl(au, filt.to_inner(), FILTER_EXISTS_TEST_THRESHOLD)
            })?;

            lfilter_info!(au, "filter executed plan -> {:?}", fplan);

            // Apply limits to the IdList.
            match &idl {
                IdList::ALLIDS => {
                    if !erl.unindexed_allow {
                        ladmin_error!(au, "filter (exists) is fully unindexed, and not allowed by resource limits");
                        return Err(OperationError::ResourceLimit);
                    }
                }
                IdList::Partial(idl_br) => {
                    if !idl_br.below_threshold(erl.search_max_filter_test) {
                        ladmin_error!(au, "filter (exists) is partial indexed and greater than search_max_filter_test allowed by resource limits");
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
                    let entries = self.get_idlayer().get_identry(au, &idl).map_err(|e| {
                        ladmin_error!(au, "get_identry failed {:?}", e);
                        e
                    })?;

                    // if not 100% resolved query, apply the filter test.
                    let entries_filtered: Vec<_> =
                        lperf_trace_segment!(au, "be::exists -> entry_match_no_index", || {
                            entries
                                .into_iter()
                                .filter(|e| e.entry_match_no_index(&filt))
                                .collect()
                        });

                    Ok(!entries_filtered.is_empty())
                }
            } // end match idl
        }) // end audit segment
    }

    fn verify(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        self.get_idlayer().verify(audit)
    }

    fn verify_entry_index(
        &self,
        audit: &mut AuditScope,
        e: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<(), ConsistencyError> {
        // First, check our references in name2uuid, uuid2spn and uuid2rdn
        if e.mask_recycled_ts().is_some() {
            let e_uuid = e.get_uuid();
            // We only check these on live entries.
            let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(None, Some(&e));

            let n2u_set = match (n2u_add, n2u_rem) {
                (Some(set), None) => set,
                (_, _) => {
                    ladmin_error!(audit, "Invalid idx_name2uuid_diff state");
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };

            // If the set.len > 1, check each item.
            n2u_set.iter().try_for_each(|name| {
                match self.get_idlayer().name2uuid(audit, name) {
                    Ok(Some(idx_uuid)) => {
                        if &idx_uuid == e_uuid {
                            Ok(())
                        } else {
                            ladmin_error!(
                                audit,
                                "Invalid name2uuid state -> incorrect uuid association"
                            );
                            Err(ConsistencyError::BackendIndexSync)
                        }
                    }
                    r => {
                        ladmin_error!(audit, "Invalid name2uuid state -> {:?}", r);
                        Err(ConsistencyError::BackendIndexSync)
                    }
                }
            })?;

            let spn = e.get_uuid2spn();
            match self.get_idlayer().uuid2spn(audit, &e_uuid) {
                Ok(Some(idx_spn)) => {
                    if spn != idx_spn {
                        ladmin_error!(audit, "Invalid uuid2spn state -> incorrect idx spn value");
                        return Err(ConsistencyError::BackendIndexSync);
                    }
                }
                r => {
                    ladmin_error!(audit, "Invalid uuid2spn state -> {:?}", r);
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };

            let rdn = e.get_uuid2rdn();
            match self.get_idlayer().uuid2rdn(audit, &e_uuid) {
                Ok(Some(idx_rdn)) => {
                    if rdn != idx_rdn {
                        ladmin_error!(audit, "Invalid uuid2rdn state -> incorrect idx rdn value");
                        return Err(ConsistencyError::BackendIndexSync);
                    }
                }
                r => {
                    ladmin_error!(audit, "Invalid uuid2rdn state -> {:?}", r);
                    return Err(ConsistencyError::BackendIndexSync);
                }
            };
        }

        // Check the other entry:attr indexes are valid
        //
        // This is acutally pretty hard to check, because we can check a value *should*
        // exist, but not that a value should NOT be present in the index. Thought needed ...

        // Got here? Ok!
        Ok(())
    }

    fn verify_indexes(&self, audit: &mut AuditScope) -> Vec<Result<(), ConsistencyError>> {
        let idl = IdList::ALLIDS;
        let entries = match self.get_idlayer().get_identry(audit, &idl) {
            Ok(s) => s,
            Err(e) => {
                ladmin_error!(audit, "get_identry failure {:?}", e);
                return vec![Err(ConsistencyError::Unknown)];
            }
        };

        let r = entries
            .iter()
            .try_for_each(|e| self.verify_entry_index(audit, e));

        if r.is_err() {
            vec![r]
        } else {
            Vec::new()
        }
    }

    fn backup(&self, audit: &mut AuditScope, dst_path: &str) -> Result<(), OperationError> {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let idl = IdList::ALLIDS;
        let raw_entries: Vec<IdRawEntry> = self.get_idlayer().get_identry_raw(audit, &idl)?;

        let entries: Result<Vec<DbEntry>, _> = raw_entries
            .iter()
            .map(|id_ent| {
                serde_cbor::from_slice(id_ent.data.as_slice())
                    .map_err(|_| OperationError::SerdeJsonError)
            })
            .collect();

        let entries = entries?;

        let serialized_entries_str = serde_json::to_string_pretty(&entries).map_err(|e| {
            ladmin_error!(audit, "serde error {:?}", e);
            OperationError::SerdeJsonError
        })?;

        fs::write(dst_path, serialized_entries_str)
            .map(|_| ())
            .map_err(|e| {
                ladmin_error!(audit, "fs::write error {:?}", e);
                OperationError::FsError
            })
    }

    fn name2uuid(
        &self,
        audit: &mut AuditScope,
        name: &str,
    ) -> Result<Option<Uuid>, OperationError> {
        self.get_idlayer().name2uuid(audit, name)
    }

    fn uuid2spn(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<Value>, OperationError> {
        self.get_idlayer().uuid2spn(audit, uuid)
    }

    fn uuid2rdn(
        &self,
        audit: &mut AuditScope,
        uuid: &Uuid,
    ) -> Result<Option<String>, OperationError> {
        self.get_idlayer().uuid2rdn(audit, uuid)
    }
}

impl<'a> BackendTransaction for BackendReadTransaction<'a> {
    type IdlLayerType = IdlArcSqliteReadTransaction<'a>;

    #[allow(clippy::mut_from_ref)]
    fn get_idlayer(&self) -> &mut IdlArcSqliteReadTransaction<'a> {
        // OKAY here be the cursed thing. We know that in our application
        // that during a transaction, that we are the only holder of the
        // idlayer, so we KNOW it can be mut, and we know every thing it
        // returns is a copy anyway. But if we permeate that mut up, it prevents
        // reference holding of read-only structures in loops, which was forcing
        // a lot of clones.
        //
        // Instead we make everything immutable, and use interior mutability
        // to the idlayer here since we know and can assert it is correct
        // that during this inner mutable phase, that nothing will be
        // conflicting during this cache operation.
        unsafe { &mut (*self.idlayer.get()) }
    }

    fn get_idxmeta_ref(&self) -> &IdxMeta {
        &self.idxmeta
    }
}

impl<'a> BackendTransaction for BackendWriteTransaction<'a> {
    type IdlLayerType = IdlArcSqliteWriteTransaction<'a>;

    #[allow(clippy::mut_from_ref)]
    fn get_idlayer(&self) -> &mut IdlArcSqliteWriteTransaction<'a> {
        unsafe { &mut (*self.idlayer.get()) }
    }

    fn get_idxmeta_ref(&self) -> &IdxMeta {
        &self.idxmeta
    }
}

impl<'a> BackendWriteTransaction<'a> {
    pub fn create(
        &self,
        au: &mut AuditScope,
        entries: Vec<Entry<EntrySealed, EntryNew>>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        lperf_trace_segment!(au, "be::create", || {
            if entries.is_empty() {
                ladmin_error!(
                    au,
                    "No entries provided to BE to create, invalid server call!"
                );
                return Err(OperationError::EmptyRequest);
            }

            let idlayer = self.get_idlayer();
            // Now, assign id's to all the new entries.

            let mut id_max = idlayer.get_id2entry_max_id()?;
            let c_entries: Vec<_> = entries
                .into_iter()
                .map(|e| {
                    id_max += 1;
                    e.into_sealed_committed_id(id_max)
                })
                .collect();

            idlayer.write_identries(au, c_entries.iter())?;

            idlayer.set_id2entry_max_id(id_max);

            // Now update the indexes as required.
            for e in c_entries.iter() {
                self.entry_index(au, None, Some(e))?
            }

            Ok(c_entries)
        })
    }

    pub fn modify(
        &self,
        au: &mut AuditScope,
        pre_entries: &[Entry<EntrySealed, EntryCommitted>],
        post_entries: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(au, "be::modify", || {
            if post_entries.is_empty() || pre_entries.is_empty() {
                ladmin_error!(
                    au,
                    "No entries provided to BE to modify, invalid server call!"
                );
                return Err(OperationError::EmptyRequest);
            }

            assert!(post_entries.len() == pre_entries.len());

            /*
            // Assert the Id's exist on the entry, and serialise them.
            // Now, that means the ID must be > 0!!!
            let ser_entries: Result<Vec<IdEntry>, _> = post_entries
                .iter()
                .map(|e| {
                    let id = i64::try_from(e.get_id())
                        .map_err(|_| OperationError::InvalidEntryId)
                        .and_then(|id| {
                            if id == 0 {
                                Err(OperationError::InvalidEntryId)
                            } else {
                                Ok(id)
                            }
                        })?;

                    Ok(IdEntry { id, data: e.clone() })
                })
                .collect();

            let ser_entries = try_audit!(au, ser_entries);

            // Simple: If the list of id's is not the same as the input list, we are missing id's
            //
            // The entry state checks prevent this from really ever being triggered, but we
            // still prefer paranoia :)
            if post_entries.len() != ser_entries.len() {
                return Err(OperationError::InvalidEntryState);
            }
            */

            // Now, given the list of id's, update them
            self.get_idlayer()
                .write_identries(au, post_entries.iter())?;

            // Finally, we now reindex all the changed entries. We do this by iterating and zipping
            // over the set, because we know the list is in the same order.
            pre_entries
                .iter()
                .zip(post_entries.iter())
                .try_for_each(|(pre, post)| self.entry_index(au, Some(pre), Some(post)))
        })
    }

    pub fn delete(
        &self,
        au: &mut AuditScope,
        entries: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        lperf_trace_segment!(au, "be::delete", || {
            if entries.is_empty() {
                ladmin_error!(
                    au,
                    "No entries provided to BE to delete, invalid server call!"
                );
                return Err(OperationError::EmptyRequest);
            }

            // Assert the id's exist on the entry.
            let id_list = entries.iter().map(|e| e.get_id());

            // Now, given the list of id's, delete them.
            self.get_idlayer().delete_identry(au, id_list)?;

            // Finally, purge the indexes from the entries we removed.
            entries
                .iter()
                .try_for_each(|e| self.entry_index(au, Some(e), None))
        })
    }

    pub fn update_idxmeta(&mut self, mut idxkeys: Set<IdxKey>) {
        std::mem::swap(&mut self.idxmeta_wr.deref_mut().idxkeys, &mut idxkeys);
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
        &self,
        audit: &mut AuditScope,
        pre: Option<&Entry<EntrySealed, EntryCommitted>>,
        post: Option<&Entry<EntrySealed, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        let (e_uuid, e_id, uuid_same) = match (pre, post) {
            (None, None) => {
                ltrace!(audit, "Invalid call to entry_index - no entries provided");
                return Err(OperationError::InvalidState);
            }
            (Some(pre), None) => {
                ltrace!(audit, "Attempting to remove entry indexes");
                (pre.get_uuid(), pre.get_id(), true)
            }
            (None, Some(post)) => {
                ltrace!(audit, "Attempting to create entry indexes");
                (post.get_uuid(), post.get_id(), true)
            }
            (Some(pre), Some(post)) => {
                ltrace!(audit, "Attempting to modify entry indexes");
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

        let idlayer = self.get_idlayer();

        let mask_pre = pre.and_then(|e| e.mask_recycled_ts());
        let mask_pre = if !uuid_same {
            // Okay, so if the uuids are different this is probably from
            // a replication conflict.  We can't just use the normal none/some
            // check from the Entry::idx functions as they only yield partial
            // changes. Because the uuid is changing, we have to treat pre
            // as a deleting entry, regardless of what state post is in.
            let uuid = mask_pre.map(|e| e.get_uuid()).ok_or_else(|| {
                ladmin_error!(audit, "Invalid entry state - possible memory corruption");
                OperationError::InvalidState
            })?;

            let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(mask_pre, None);
            // There will never be content to add.
            assert!(n2u_add.is_none());

            let u2s_act = Entry::idx_uuid2spn_diff(mask_pre, None);
            let u2r_act = Entry::idx_uuid2rdn_diff(mask_pre, None);

            ltrace!(audit, "!uuid_same n2u_rem -> {:?}", n2u_rem);
            ltrace!(audit, "!uuid_same u2s_act -> {:?}", u2s_act);
            ltrace!(audit, "!uuid_same u2r_act -> {:?}", u2r_act);

            // Write the changes out to the backend
            if let Some(rem) = n2u_rem {
                idlayer.write_name2uuid_rem(audit, rem)?
            }

            match u2s_act {
                None => {}
                Some(Ok(k)) => idlayer.write_uuid2spn(audit, uuid, Some(k))?,
                Some(Err(_)) => idlayer.write_uuid2spn(audit, uuid, None)?,
            }

            match u2r_act {
                None => {}
                Some(Ok(k)) => idlayer.write_uuid2rdn(audit, uuid, Some(k))?,
                Some(Err(_)) => idlayer.write_uuid2rdn(audit, uuid, None)?,
            }
            // Return none, mask_pre is now completed.
            None
        } else {
            // Return the state.
            mask_pre
        };

        let mask_post = post.and_then(|e| e.mask_recycled_ts());
        let (n2u_add, n2u_rem) = Entry::idx_name2uuid_diff(mask_pre, mask_post);

        let u2s_act = Entry::idx_uuid2spn_diff(mask_pre, mask_post);
        let u2r_act = Entry::idx_uuid2rdn_diff(mask_pre, mask_post);

        ltrace!(audit, "n2u_add -> {:?}", n2u_add);
        ltrace!(audit, "n2u_rem -> {:?}", n2u_rem);
        ltrace!(audit, "u2s_act -> {:?}", u2s_act);
        ltrace!(audit, "u2r_act -> {:?}", u2r_act);

        // Write the changes out to the backend
        if let Some(add) = n2u_add {
            idlayer.write_name2uuid_add(audit, e_uuid, add)?
        }
        if let Some(rem) = n2u_rem {
            idlayer.write_name2uuid_rem(audit, rem)?
        }

        match u2s_act {
            None => {}
            Some(Ok(k)) => idlayer.write_uuid2spn(audit, e_uuid, Some(k))?,
            Some(Err(_)) => idlayer.write_uuid2spn(audit, e_uuid, None)?,
        }

        match u2r_act {
            None => {}
            Some(Ok(k)) => idlayer.write_uuid2rdn(audit, e_uuid, Some(k))?,
            Some(Err(_)) => idlayer.write_uuid2rdn(audit, e_uuid, None)?,
        }

        // Extremely Cursed - Okay, we know that self.idxmeta will NOT be changed
        // in this function, but we need to borrow self as mut for the caches in
        // get_idl to work. As a result, this causes a double borrow. To work around
        // this we discard the lifetime on idxmeta, because we know that it will
        // remain constant for the life of the operation.

        let idxmeta = unsafe { &(*(&self.idxmeta.idxkeys as *const _)) };

        let idx_diff = Entry::idx_diff(&(*idxmeta), pre, post);

        idx_diff.iter()
            .try_for_each(|act| {
                match act {
                    Ok((attr, itype, idx_key)) => {
                        ltrace!(audit, "Adding {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match idlayer.get_idl(audit, attr, itype, idx_key)? {
                            Some(mut idl) => {
                                idl.insert_id(e_id);
                                idlayer.write_idl(audit, attr, itype, idx_key, &idl)
                            }
                            None => {
                                ladmin_error!(
                                    audit,
                                    "WARNING: index {:?} {:?} was not found. YOU MUST REINDEX YOUR DATABASE",
                                    attr, itype
                                );
                                Ok(())
                            }
                        }
                    }
                    Err((attr, itype, idx_key)) => {
                        ltrace!(audit, "Removing {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match idlayer.get_idl(audit, attr, itype, idx_key)? {
                            Some(mut idl) => {
                                idl.remove_id(e_id);
                                idlayer.write_idl(audit, attr, itype, idx_key, &idl)
                            }
                            None => {
                                ladmin_error!(
                                    audit,
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
    fn missing_idxs(
        &self,
        audit: &mut AuditScope,
    ) -> Result<Vec<(AttrString, IndexType)>, OperationError> {
        let idx_table_list = self.get_idlayer().list_idxs(audit)?;

        // Turn the vec to a real set
        let idx_table_set: Set<_> = idx_table_list.into_iter().collect();

        let missing: Vec<_> = self
            .idxmeta
            .idxkeys
            .iter()
            .filter_map(|ikey| {
                // what would the table name be?
                let tname = format!("idx_{}_{}", ikey.itype.as_idx_str(), ikey.attr.as_str());
                ltrace!(audit, "Checking for {}", tname);

                if idx_table_set.contains(&tname) {
                    None
                } else {
                    Some((ikey.attr.clone(), ikey.itype.clone()))
                }
            })
            .collect();
        Ok(missing)
    }

    fn create_idxs(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let idlayer = self.get_idlayer();
        // Create name2uuid and uuid2name
        ltrace!(audit, "Creating index -> name2uuid");
        idlayer.create_name2uuid(audit)?;

        ltrace!(audit, "Creating index -> uuid2spn");
        idlayer.create_uuid2spn(audit)?;

        ltrace!(audit, "Creating index -> uuid2rdn");
        idlayer.create_uuid2rdn(audit)?;

        self.idxmeta
            .idxkeys
            .iter()
            .try_for_each(|ikey| idlayer.create_idx(audit, &ikey.attr, &ikey.itype))
    }

    pub fn upgrade_reindex(&self, audit: &mut AuditScope, v: i64) -> Result<(), OperationError> {
        let dbv = self.get_db_index_version();
        ladmin_info!(audit, "upgrade_reindex -> dbv: {} v: {}", dbv, v);
        if dbv < v {
            limmediate_warning!(
                audit,
                "NOTICE: A system reindex is required. This may take a long time ...\n"
            );
            self.reindex(audit)?;
            limmediate_warning!(audit, "NOTICE: System reindex complete\n");
            self.set_db_index_version(v)
        } else {
            Ok(())
        }
    }

    pub fn reindex(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let idlayer = self.get_idlayer();
        // Purge the idxs
        unsafe { idlayer.purge_idxs(audit)? };

        // Using the index metadata on the txn, create all our idx tables
        self.create_idxs(audit)?;

        // Now, we need to iterate over everything in id2entry and index them
        // Future idea: Do this in batches of X amount to limit memory
        // consumption.
        let idl = IdList::ALLIDS;
        let entries = idlayer.get_identry(audit, &idl).map_err(|e| {
            ladmin_error!(audit, "get_identry failure {:?}", e);
            e
        })?;

        let mut count = 0;

        entries
            .iter()
            .try_for_each(|e| {
                count += 1;
                if count % 2500 == 0 {
                    limmediate_warning!(audit, "{}", count);
                } else if count % 250 == 0 {
                    limmediate_warning!(audit, ".");
                }
                self.entry_index(audit, None, Some(e))
            })
            .map_err(|e| {
                ladmin_error!(audit, "reindex failed -> {:?}", e);
                e
            })?;
        limmediate_warning!(audit, " reindexed {} entries ✅\n", count);
        limmediate_warning!(audit, "Optimising Indexes ... ");
        idlayer.optimise_dirty_idls(audit);
        limmediate_warning!(audit, "done ✅\n");

        Ok(())
    }

    #[cfg(test)]
    pub fn purge_idxs(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unsafe { self.get_idlayer().purge_idxs(audit) }
    }

    #[cfg(test)]
    pub fn load_test_idl(
        &self,
        audit: &mut AuditScope,
        attr: &String,
        itype: &IndexType,
        idx_key: &String,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        self.get_idlayer().get_idl(audit, attr, itype, idx_key)
    }

    pub fn restore(&self, audit: &mut AuditScope, src_path: &str) -> Result<(), OperationError> {
        let idlayer = self.get_idlayer();
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let serialized_string = fs::read_to_string(src_path).map_err(|e| {
            ladmin_error!(audit, "fs::read_to_string {:?}", e);
            OperationError::FsError
        })?;

        unsafe { idlayer.purge_id2entry(audit) }.map_err(|e| {
            ladmin_error!(audit, "purge_id2entry failed {:?}", e);
            e
        })?;

        let dbentries_option: Result<Vec<DbEntry>, serde_json::Error> =
            serde_json::from_str(&serialized_string);

        let dbentries = dbentries_option.map_err(|e| {
            ladmin_error!(audit, "serde_json error {:?}", e);
            OperationError::SerdeJsonError
        })?;

        // Filter all elements that have a UUID in the system range.
        /*
        use crate::constants::UUID_ANONYMOUS;
        use crate::be::dbentry::DbEntryVers;
        use crate::be::dbvalue::DbValueV1;
        let uuid_anonymous = UUID_ANONYMOUS.clone();
        let dbentries: Vec<DbEntry> = dbentries.into_iter()
            .filter(|e| {
                let e_uuid = match &e.ent {
                    DbEntryVers::V1(dbe) => dbe.attrs.get("uuid")
                        .and_then(|dbvs| dbvs.first())
                        .and_then(|dbv| {
                            match dbv {
                                DbValueV1::UU(u) => Some(u),
                                _ => panic!(),
                            }
                        })
                        .unwrap()
                };

                e_uuid > &uuid_anonymous
            })
            .collect();

        dbentries.iter().for_each(|e| {
            ltrace!(audit, "importing -> {:?}", e);
        });
        */

        // Now, we setup all the entries with new ids.
        let mut id_max = 0;
        let identries: Result<Vec<IdRawEntry>, _> = dbentries
            .iter()
            .map(|e| {
                id_max += 1;
                let data = serde_cbor::to_vec(&e).map_err(|_| OperationError::SerdeCborError)?;
                Ok(IdRawEntry { id: id_max, data })
            })
            .collect();

        idlayer.write_identries_raw(audit, identries?.into_iter())?;

        // for debug
        /*
        self.idlayer.get_identry(audit, &IdList::ALLIDS)
            .unwrap()
            .iter()
            .for_each(|dbe| {
                ltrace!(audit, "dbe -> {:?}", dbe.id);
            });
        */

        // Reindex now we are loaded.
        self.reindex(audit)?;

        let vr = self.verify(audit);
        if vr.is_empty() {
            Ok(())
        } else {
            Err(OperationError::ConsistencyError(vr))
        }
    }

    pub fn commit(self, audit: &mut AuditScope) -> Result<(), OperationError> {
        let BackendWriteTransaction {
            idlayer,
            idxmeta: _,
            idxmeta_wr,
        } = self;

        // Unwrap the Cell we have finished with it.
        let idlayer = idlayer.into_inner();

        idlayer.commit(audit).map(|()| {
            idxmeta_wr.commit();
        })
    }

    fn reset_db_s_uuid(&self) -> Result<Uuid, OperationError> {
        // The value is missing. Generate a new one and store it.
        let nsid = Uuid::new_v4();
        self.get_idlayer().write_db_s_uuid(nsid)?;
        Ok(nsid)
    }

    pub fn get_db_s_uuid(&self) -> Uuid {
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

    fn reset_db_d_uuid(&self) -> Result<Uuid, OperationError> {
        let nsid = Uuid::new_v4();
        self.get_idlayer().write_db_d_uuid(nsid)?;
        Ok(nsid)
    }

    pub fn get_db_d_uuid(&self) -> Uuid {
        #[allow(clippy::expect_used)]
        match self
            .get_idlayer()
            .get_db_d_uuid()
            .expect("DBLayer Error!!!")
        {
            Some(d_uuid) => d_uuid,
            None => self.reset_db_d_uuid().expect("Failed to regenerate D_UUID"),
        }
    }

    pub fn set_db_ts_max(&self, ts: &Duration) -> Result<(), OperationError> {
        self.get_idlayer().set_db_ts_max(ts)
    }

    pub fn get_db_ts_max(&self, ts: &Duration) -> Result<Duration, OperationError> {
        // if none, return ts. If found, return it.
        match self.get_idlayer().get_db_ts_max()? {
            Some(dts) => Ok(dts),
            None => Ok(*ts),
        }
    }

    fn get_db_index_version(&self) -> i64 {
        self.get_idlayer().get_db_index_version()
    }

    fn set_db_index_version(&self, v: i64) -> Result<(), OperationError> {
        self.get_idlayer().set_db_index_version(v)
    }
}

// In the future this will do the routing between the chosen backends etc.
impl Backend {
    pub fn new(
        audit: &mut AuditScope,
        mut cfg: BackendConfig,
        // path: &str,
        // mut pool_size: u32,
        // fstype: FsType,
        idxkeys: Set<IdxKey>,
        vacuum: bool,
    ) -> Result<Self, OperationError> {
        info!("DB tickets -> {:?}", cfg.pool_size);
        info!("Profile -> {}", env!("KANIDM_PROFILE_NAME"));
        info!("CPU Flags -> {}", env!("KANIDM_CPU_FLAGS"));

        // If in memory, reduce pool to 1
        if cfg.path.is_empty() {
            cfg.pool_size = 1;
        }

        // this has a ::memory() type, but will path == "" work?
        lperf_trace_segment!(audit, "be::new", || {
            let idlayer = Arc::new(IdlArcSqlite::new(audit, &cfg, vacuum)?);
            let be = Backend {
                cfg,
                idlayer,
                idxmeta: Arc::new(CowCell::new(IdxMeta::new(idxkeys))),
            };

            // Now complete our setup with a txn
            // In this case we can use an empty idx meta because we don't
            // access any parts of
            // the indexing subsystem here.
            let r = {
                let mut idl_write = be.idlayer.write();
                idl_write.setup(audit).and_then(|_| idl_write.commit(audit))
            };

            ltrace!(audit, "be new setup: {:?}", r);

            match r {
                Ok(_) => Ok(be),
                Err(e) => Err(e),
            }
        })
    }

    pub fn get_pool_size(&self) -> u32 {
        debug_assert!(self.cfg.pool_size > 0);
        self.cfg.pool_size
    }

    pub fn read(&self) -> BackendReadTransaction {
        BackendReadTransaction {
            idlayer: UnsafeCell::new(self.idlayer.read()),
            idxmeta: self.idxmeta.read(),
        }
    }

    pub fn write(&self) -> BackendWriteTransaction {
        BackendWriteTransaction {
            idlayer: UnsafeCell::new(self.idlayer.write()),
            idxmeta: self.idxmeta.read(),
            idxmeta_wr: self.idxmeta.write(),
        }
    }

    // Should this actually call the idlayer directly?
    pub fn reset_db_s_uuid(&self, audit: &mut AuditScope) -> Uuid {
        let wr = self.write();
        #[allow(clippy::expect_used)]
        let sid = wr
            .reset_db_s_uuid()
            .expect("unable to reset db server uuid");
        #[allow(clippy::expect_used)]
        wr.commit(audit)
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

// What are the possible actions we'll recieve here?

#[cfg(test)]
mod tests {
    use hashbrown::HashSet as Set;
    use idlset::v2::IDLBitRange;
    use std::fs;
    use std::iter::FromIterator;
    use uuid::Uuid;

    use super::super::audit::AuditScope;
    use super::super::entry::{Entry, EntryInit, EntryNew};
    use super::IdxKey;
    use super::{
        Backend, BackendConfig, BackendTransaction, BackendWriteTransaction, IdList, OperationError,
    };
    use crate::event::EventLimits;
    use crate::value::{IndexType, PartialValue, Value};
    use smartstring::alias::String as AttrString;

    macro_rules! run_test {
        ($test_fn:expr) => {{
            use env_logger;
            ::std::env::set_var("RUST_LOG", "kanidm=debug");
            let _ = env_logger::builder()
                .format_timestamp(None)
                .format_level(false)
                .is_test(true)
                .try_init();

            let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

            // This is a demo idxmeta, purely for testing.
            let mut idxmeta = Set::with_capacity(16);
            idxmeta.insert(IdxKey {
                attr: AttrString::from("name"),
                itype: IndexType::EQUALITY,
            });
            idxmeta.insert(IdxKey {
                attr: AttrString::from("name"),
                itype: IndexType::PRESENCE,
            });
            idxmeta.insert(IdxKey {
                attr: AttrString::from("name"),
                itype: IndexType::SUBSTRING,
            });
            idxmeta.insert(IdxKey {
                attr: AttrString::from("uuid"),
                itype: IndexType::EQUALITY,
            });
            idxmeta.insert(IdxKey {
                attr: AttrString::from("uuid"),
                itype: IndexType::PRESENCE,
            });
            idxmeta.insert(IdxKey {
                attr: AttrString::from("ta"),
                itype: IndexType::EQUALITY,
            });
            idxmeta.insert(IdxKey {
                attr: AttrString::from("tb"),
                itype: IndexType::EQUALITY,
            });

            let be = Backend::new(&mut audit, BackendConfig::new_test(), idxmeta, false)
                .expect("Failed to setup backend");

            let mut be_txn = be.write();

            let r = $test_fn(&mut audit, &mut be_txn);
            // Commit, to guarantee it worked.
            assert!(be_txn.commit(&mut audit).is_ok());
            audit.write_log();
            r
        }};
    }

    macro_rules! entry_exists {
        ($audit:expr, $be:expr, $ent:expr) => {{
            let ei = unsafe { $ent.clone().into_sealed_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![AttrString::from("userid")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            let lims = EventLimits::unlimited();
            let entries = $be.search($audit, &lims, &filt).expect("failed to search");
            entries.first().is_some()
        }};
    }

    macro_rules! entry_attr_pres {
        ($audit:expr, $be:expr, $ent:expr, $attr:expr) => {{
            let ei = unsafe { $ent.clone().into_sealed_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![AttrString::from("userid")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            let lims = EventLimits::unlimited();
            let entries = $be.search($audit, &lims, &filt).expect("failed to search");
            match entries.first() {
                Some(ent) => ent.attribute_pres($attr),
                None => false,
            }
        }};
    }

    macro_rules! idl_state {
        ($audit:expr, $be:expr, $attr:expr, $itype:expr, $idx_key:expr, $expect:expr) => {{
            let t_idl = $be
                .load_test_idl($audit, &$attr.to_string(), &$itype, &$idx_key.to_string())
                .expect("IdList Load failed");
            let t = $expect.map(|v: Vec<u64>| IDLBitRange::from_iter(v));
            assert_eq!(t_idl, t);
        }};
    }

    #[test]
    fn test_be_simple_create() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            ltrace!(audit, "Simple Create");

            let empty_result = be.create(audit, Vec::new());
            ltrace!(audit, "{:?}", empty_result);
            assert_eq!(empty_result, Err(OperationError::EmptyRequest));

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e = unsafe { e.into_sealed_new() };

            let single_result = be.create(audit, vec![e.clone()]);

            assert!(single_result.is_ok());

            // Construct a filter
            assert!(entry_exists!(audit, be, e));
        });
    }

    #[test]
    fn test_be_simple_search() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            ltrace!(audit, "Simple Search");

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("claire"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e = unsafe { e.into_sealed_new() };

            let single_result = be.create(audit, vec![e.clone()]);
            assert!(single_result.is_ok());
            // Test a simple EQ search

            let filt =
                unsafe { filter_resolved!(f_eq("userid", PartialValue::new_utf8s("claire"))) };

            let lims = EventLimits::unlimited();

            let r = be.search(audit, &lims, &filt);
            assert!(r.expect("Search failed!").len() == 1);

            // Test empty search

            // Test class pres

            // Search with no results
        });
    }

    #[test]
    fn test_be_simple_modify() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            ltrace!(audit, "Simple Modify");
            let lims = EventLimits::unlimited();
            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", Value::from("alice"));
            e2.add_ava("uuid", Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };

            assert!(be.create(audit, vec![ve1, ve2]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(audit, &lims, unsafe { &filter_resolved!(f_pres("userid")) })
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);

            let mut r1 = unsafe { r1.into_invalid() };
            let mut r2 = unsafe { r2.into_invalid() };

            // Modify no id (err)
            // This is now impossible due to the state machine design.
            // However, with some unsafe ....
            let ue1 = unsafe { e1.clone().into_sealed_committed() };
            assert!(be.modify(audit, &vec![ue1.clone()], &vec![ue1]).is_err());
            // Modify none
            assert!(be.modify(audit, &vec![], &vec![]).is_err());

            // Make some changes to r1, r2.
            let pre1 = unsafe { r1.clone().into_sealed_committed() };
            let pre2 = unsafe { r2.clone().into_sealed_committed() };
            r1.add_ava("desc", Value::from("modified"));
            r2.add_ava("desc", Value::from("modified"));

            // Now ... cheat.

            let vr1 = unsafe { r1.into_sealed_committed() };
            let vr2 = unsafe { r2.into_sealed_committed() };

            // Modify single
            assert!(be
                .modify(audit, &vec![pre1.clone()], &vec![vr1.clone()])
                .is_ok());
            // Assert no other changes
            assert!(entry_attr_pres!(audit, be, vr1, "desc"));
            assert!(!entry_attr_pres!(audit, be, vr2, "desc"));

            // Modify both
            assert!(be
                .modify(
                    audit,
                    &vec![vr1.clone(), pre2.clone()],
                    &vec![vr1.clone(), vr2.clone()]
                )
                .is_ok());

            assert!(entry_attr_pres!(audit, be, vr1, "desc"));
            assert!(entry_attr_pres!(audit, be, vr2, "desc"));
        });
    }

    #[test]
    fn test_be_simple_delete() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            ltrace!(audit, "Simple Delete");
            let lims = EventLimits::unlimited();

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

            assert!(be.create(audit, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));
            assert!(entry_exists!(audit, be, e3));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(audit, &lims, unsafe { &filter_resolved!(f_pres("userid")) })
                .expect("Failed to search");

            // Get these out to usable entries.
            let r1 = results.remove(0);
            let r2 = results.remove(0);
            let r3 = results.remove(0);

            // Delete one
            assert!(be.delete(audit, &vec![r1.clone()]).is_ok());
            assert!(!entry_exists!(audit, be, r1));

            // delete none (no match filter)
            assert!(be.delete(audit, &vec![]).is_err());

            // Delete with no id
            // WARNING: Normally, this isn't possible, but we are pursposefully breaking
            // the state machine rules here!!!!
            let mut e4: Entry<EntryInit, EntryNew> = Entry::new();
            e4.add_ava("userid", Value::from("amy"));
            e4.add_ava("uuid", Value::from("21d816b5-1f6a-4696-b7c1-6ed06d22ed81"));

            let ve4 = unsafe { e4.clone().into_sealed_committed() };

            assert!(be.delete(audit, &vec![ve4]).is_err());

            assert!(entry_exists!(audit, be, r2));
            assert!(entry_exists!(audit, be, r3));

            // delete batch
            assert!(be.delete(audit, &vec![r2.clone(), r3.clone()]).is_ok());

            assert!(!entry_exists!(audit, be, r2));
            assert!(!entry_exists!(audit, be, r3));

            // delete none (no entries left)
            // see fn delete for why this is ok, not err
            assert!(be.delete(audit, &vec![r2.clone(), r3.clone()]).is_ok());
        });
    }

    pub const DB_BACKUP_FILE_NAME: &'static str = "./.backup_test.db";

    #[test]
    fn test_be_backup_restore() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
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

            assert!(be.create(audit, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));
            assert!(entry_exists!(audit, be, e3));

            let result = fs::remove_file(DB_BACKUP_FILE_NAME);

            match result {
                Err(e) => {
                    // if the error is the file is not found, thats what we want so continue,
                    // otherwise return the error
                    match e.kind() {
                        std::io::ErrorKind::NotFound => {}
                        _ => (),
                    }
                }
                _ => (),
            }

            be.backup(audit, DB_BACKUP_FILE_NAME)
                .expect("Backup failed!");
            be.restore(audit, DB_BACKUP_FILE_NAME)
                .expect("Restore failed!");
        });
    }

    #[test]
    fn test_be_sid_generation_and_reset() {
        run_test!(
            |_audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
                let sid1 = be.get_db_s_uuid();
                let sid2 = be.get_db_s_uuid();
                assert!(sid1 == sid2);
                let sid3 = be.reset_db_s_uuid().unwrap();
                assert!(sid1 != sid3);
                let sid4 = be.get_db_s_uuid();
                assert!(sid3 == sid4);
            }
        );
    }

    #[test]
    fn test_be_reindex_empty() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            // Add some test data?
            let missing = be.missing_idxs(audit).unwrap();
            assert!(missing.len() == 7);
            assert!(be.reindex(audit).is_ok());
            let missing = be.missing_idxs(audit).unwrap();
            debug!("{:?}", missing);
            assert!(missing.is_empty());
        });
    }

    #[test]
    fn test_be_reindex_data() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            // Add some test data?
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::new_iname("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::new_iname("claire"));
            e2.add_ava("uuid", Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"));
            let e2 = unsafe { e2.into_sealed_new() };

            be.create(audit, vec![e1.clone(), e2.clone()]).unwrap();

            // purge indexes
            be.purge_idxs(audit).unwrap();
            // Check they are gone
            let missing = be.missing_idxs(audit).unwrap();
            assert!(missing.len() == 7);
            assert!(be.reindex(audit).is_ok());
            let missing = be.missing_idxs(audit).unwrap();
            debug!("{:?}", missing);
            assert!(missing.is_empty());
            // check name and uuid ids on eq, sub, pres

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "william",
                Some(vec![1])
            );

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "claire",
                Some(vec![2])
            );

            idl_state!(
                audit,
                be,
                "name",
                IndexType::PRESENCE,
                "_",
                Some(vec![1, 2])
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(vec![1])
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "bd651620-00dd-426b-aaa0-4494f7b7906f",
                Some(vec![2])
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::PRESENCE,
                "_",
                Some(vec![1, 2])
            );

            // Show what happens with empty

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "not-exist",
                Some(Vec::new())
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "fake-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::new())
            );

            let uuid_p_idl = be
                .load_test_idl(
                    audit,
                    &"not_indexed".to_string(),
                    &IndexType::PRESENCE,
                    &"_".to_string(),
                )
                .unwrap(); // unwrap the result
            assert_eq!(uuid_p_idl, None);

            // Check name2uuid
            let claire_uuid = Uuid::parse_str("bd651620-00dd-426b-aaa0-4494f7b7906f").unwrap();
            let william_uuid = Uuid::parse_str("db237e8a-0079-4b8c-8a56-593b22aa44d1").unwrap();

            assert!(be.name2uuid(audit, "claire") == Ok(Some(claire_uuid)));
            assert!(be.name2uuid(audit, "william") == Ok(Some(william_uuid)));
            assert!(be.name2uuid(audit, "db237e8a-0079-4b8c-8a56-593b22aa44d1") == Ok(None));
            // check uuid2spn
            assert!(be.uuid2spn(audit, &claire_uuid) == Ok(Some(Value::new_iname("claire"))));
            assert!(be.uuid2spn(audit, &william_uuid) == Ok(Some(Value::new_iname("william"))));
            // check uuid2rdn
            assert!(be.uuid2rdn(audit, &claire_uuid) == Ok(Some("name=claire".to_string())));
            assert!(be.uuid2rdn(audit, &william_uuid) == Ok(Some("name=william".to_string())));
        });
    }

    #[test]
    fn test_be_index_create_delete_simple() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            // First, setup our index tables!
            assert!(be.reindex(audit).is_ok());
            // Test that on entry create, the indexes are made correctly.
            // this is a similar case to reindex.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(audit, vec![e1.clone()]).unwrap();

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "william",
                Some(vec![1])
            );

            idl_state!(audit, be, "name", IndexType::PRESENCE, "_", Some(vec![1]));

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(vec![1])
            );

            idl_state!(audit, be, "uuid", IndexType::PRESENCE, "_", Some(vec![1]));

            let william_uuid = Uuid::parse_str("db237e8a-0079-4b8c-8a56-593b22aa44d1").unwrap();
            assert!(be.name2uuid(audit, "william") == Ok(Some(william_uuid)));
            assert!(be.uuid2spn(audit, &william_uuid) == Ok(Some(Value::from("william"))));
            assert!(be.uuid2rdn(audit, &william_uuid) == Ok(Some("name=william".to_string())));

            // == Now we delete, and assert we removed the items.
            be.delete(audit, &rset).unwrap();

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "william",
                Some(Vec::new())
            );

            idl_state!(
                audit,
                be,
                "name",
                IndexType::PRESENCE,
                "_",
                Some(Vec::new())
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::new())
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::PRESENCE,
                "_",
                Some(Vec::new())
            );

            assert!(be.name2uuid(audit, "william") == Ok(None));
            assert!(be.uuid2spn(audit, &william_uuid) == Ok(None));
            assert!(be.uuid2rdn(audit, &william_uuid) == Ok(None));
        })
    }

    #[test]
    fn test_be_index_create_delete_multi() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            // delete multiple entries at a time, without deleting others
            // First, setup our index tables!
            assert!(be.reindex(audit).is_ok());
            // Test that on entry create, the indexes are made correctly.
            // this is a similar case to reindex.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::from("claire"));
            e2.add_ava("uuid", Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"));
            let e2 = unsafe { e2.into_sealed_new() };

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", Value::from("lucy"));
            e3.add_ava("uuid", Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));
            let e3 = unsafe { e3.into_sealed_new() };

            let mut rset = be
                .create(audit, vec![e1.clone(), e2.clone(), e3.clone()])
                .unwrap();
            rset.remove(1);

            // Now remove e1, e3.
            be.delete(audit, &rset).unwrap();

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "claire",
                Some(vec![2])
            );

            idl_state!(audit, be, "name", IndexType::PRESENCE, "_", Some(vec![2]));

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "bd651620-00dd-426b-aaa0-4494f7b7906f",
                Some(vec![2])
            );

            idl_state!(audit, be, "uuid", IndexType::PRESENCE, "_", Some(vec![2]));

            let claire_uuid = Uuid::parse_str("bd651620-00dd-426b-aaa0-4494f7b7906f").unwrap();
            let william_uuid = Uuid::parse_str("db237e8a-0079-4b8c-8a56-593b22aa44d1").unwrap();
            let lucy_uuid = Uuid::parse_str("7b23c99d-c06b-4a9a-a958-3afa56383e1d").unwrap();

            assert!(be.name2uuid(audit, "claire") == Ok(Some(claire_uuid)));
            assert!(be.uuid2spn(audit, &claire_uuid) == Ok(Some(Value::from("claire"))));
            assert!(be.uuid2rdn(audit, &claire_uuid) == Ok(Some("name=claire".to_string())));

            assert!(be.name2uuid(audit, "william") == Ok(None));
            assert!(be.uuid2spn(audit, &william_uuid) == Ok(None));
            assert!(be.uuid2rdn(audit, &william_uuid) == Ok(None));

            assert!(be.name2uuid(audit, "lucy") == Ok(None));
            assert!(be.uuid2spn(audit, &lucy_uuid) == Ok(None));
            assert!(be.uuid2rdn(audit, &lucy_uuid) == Ok(None));
        })
    }

    #[test]
    fn test_be_index_modify_simple() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            assert!(be.reindex(audit).is_ok());
            // modify with one type, ensuring we clean the indexes behind
            // us. For the test to be "accurate" we must add one attr, remove one attr
            // and change one attr.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("ta", Value::from("test"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(audit, vec![e1.clone()]).unwrap();
            // Now, alter the new entry.
            let mut ce1 = unsafe { rset[0].clone().into_invalid() };
            // add something.
            ce1.add_ava("tb", Value::from("test"));
            // remove something.
            ce1.purge_ava("ta");
            // mod something.
            ce1.purge_ava("name");
            ce1.add_ava("name", Value::from("claire"));

            let ce1 = unsafe { ce1.into_sealed_committed() };

            be.modify(audit, &rset, &vec![ce1]).unwrap();

            // Now check the idls
            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "claire",
                Some(vec![1])
            );

            idl_state!(audit, be, "name", IndexType::PRESENCE, "_", Some(vec![1]));

            idl_state!(audit, be, "tb", IndexType::EQUALITY, "test", Some(vec![1]));

            idl_state!(audit, be, "ta", IndexType::EQUALITY, "test", Some(vec![]));

            // let claire_uuid = Uuid::parse_str("bd651620-00dd-426b-aaa0-4494f7b7906f").unwrap();
            let william_uuid = Uuid::parse_str("db237e8a-0079-4b8c-8a56-593b22aa44d1").unwrap();
            assert!(be.name2uuid(audit, "william") == Ok(None));
            assert!(be.name2uuid(audit, "claire") == Ok(Some(william_uuid)));
            assert!(be.uuid2spn(audit, &william_uuid) == Ok(Some(Value::from("claire"))));
            assert!(be.uuid2rdn(audit, &william_uuid) == Ok(Some("name=claire".to_string())));
        })
    }

    #[test]
    fn test_be_index_modify_rename() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            assert!(be.reindex(audit).is_ok());
            // test when we change name AND uuid
            // This will be needing to be correct for conflicts when we add
            // replication support!
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(audit, vec![e1.clone()]).unwrap();
            // Now, alter the new entry.
            let mut ce1 = unsafe { rset[0].clone().into_invalid() };
            ce1.purge_ava("name");
            ce1.purge_ava("uuid");
            ce1.add_ava("name", Value::from("claire"));
            ce1.add_ava("uuid", Value::from("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8"));
            let ce1 = unsafe { ce1.into_sealed_committed() };

            be.modify(audit, &rset, &vec![ce1]).unwrap();

            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "claire",
                Some(vec![1])
            );

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "04091a7a-6ce4-42d2-abf5-c2ce244ac9e8",
                Some(vec![1])
            );

            idl_state!(audit, be, "name", IndexType::PRESENCE, "_", Some(vec![1]));
            idl_state!(audit, be, "uuid", IndexType::PRESENCE, "_", Some(vec![1]));

            idl_state!(
                audit,
                be,
                "uuid",
                IndexType::EQUALITY,
                "db237e8a-0079-4b8c-8a56-593b22aa44d1",
                Some(Vec::new())
            );
            idl_state!(
                audit,
                be,
                "name",
                IndexType::EQUALITY,
                "william",
                Some(Vec::new())
            );

            let claire_uuid = Uuid::parse_str("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8").unwrap();
            let william_uuid = Uuid::parse_str("db237e8a-0079-4b8c-8a56-593b22aa44d1").unwrap();
            assert!(be.name2uuid(audit, "william") == Ok(None));
            assert!(be.name2uuid(audit, "claire") == Ok(Some(claire_uuid)));
            assert!(be.uuid2spn(audit, &william_uuid) == Ok(None));
            assert!(be.uuid2rdn(audit, &william_uuid) == Ok(None));
            assert!(be.uuid2spn(audit, &claire_uuid) == Ok(Some(Value::from("claire"))));
            assert!(be.uuid2rdn(audit, &claire_uuid) == Ok(Some("name=claire".to_string())));
        })
    }

    #[test]
    fn test_be_index_search_simple() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            assert!(be.reindex(audit).is_ok());

            // Create a test entry with some indexed / unindexed values.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", Value::from("william"));
            e1.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("no-index", Value::from("william"));
            e1.add_ava("other-no-index", Value::from("william"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", Value::from("claire"));
            e2.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d2"));
            let e2 = unsafe { e2.into_sealed_new() };

            let _rset = be.create(audit, vec![e1.clone(), e2.clone()]).unwrap();
            // Test fully unindexed
            let f_un =
                unsafe { filter_resolved!(f_eq("no-index", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(audit, f_un.to_inner(), 0).unwrap();
            match r {
                IdList::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }

            // Test that a fully indexed search works
            let f_eq =
                unsafe { filter_resolved!(f_eq("name", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(audit, f_eq.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_in_and.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_p1.to_inner(), 0).unwrap();
            match r {
                IdList::Partial(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            let (r, _plan) = be.filter2idl(audit, f_p2.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_no_and.to_inner(), 0).unwrap();
            match r {
                IdList::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }

            //   full index or
            let f_in_or = unsafe {
                filter_resolved!(f_or!([f_eq("name", PartialValue::new_utf8s("william"))]))
            };

            let (r, _plan) = be.filter2idl(audit, f_in_or.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_un_or.to_inner(), 0).unwrap();
            match r {
                IdList::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }

            // Test root andnot
            let f_r_andnot = unsafe {
                filter_resolved!(f_andnot(f_eq("name", PartialValue::new_utf8s("william"))))
            };

            let (r, _plan) = be.filter2idl(audit, f_r_andnot.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_and_andnot.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_or_andnot.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_and_andnot.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_and_andnot.to_inner(), 0).unwrap();
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

            let (r, _plan) = be.filter2idl(audit, f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::ALLIDS => {}
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

            let (r, _plan) = be.filter2idl(audit, f_and_andnot.to_inner(), 0).unwrap();
            match r {
                IdList::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }

            //   empty or
            let f_e_or = unsafe { filter_resolved!(f_or!([])) };

            let (r, _plan) = be.filter2idl(audit, f_e_or.to_inner(), 0).unwrap();
            match r {
                IdList::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![]));
                }
                _ => {
                    panic!("");
                }
            }

            let f_e_and = unsafe { filter_resolved!(f_and!([])) };

            let (r, _plan) = be.filter2idl(audit, f_e_and.to_inner(), 0).unwrap();
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
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            // Test where the index is in schema but not created (purge idxs)
            // should fall back to an empty set because we can't satisfy the term
            be.purge_idxs(audit).unwrap();
            debug!("{:?}", be.missing_idxs(audit).unwrap());
            let f_eq =
                unsafe { filter_resolved!(f_eq("name", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(audit, f_eq.to_inner(), 0).unwrap();
            match r {
                IdList::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }
        })
    }

    #[test]
    fn test_be_limits_allids() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            let mut lim_allow_allids = EventLimits::unlimited();
            lim_allow_allids.unindexed_allow = true;

            let mut lim_deny_allids = EventLimits::unlimited();
            lim_deny_allids.unindexed_allow = false;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e.add_ava("nonexist", Value::from("x"));
            let e = unsafe { e.into_sealed_new() };
            let single_result = be.create(audit, vec![e.clone()]);

            assert!(single_result.is_ok());
            let filt = unsafe {
                e.filter_from_attrs(&vec![AttrString::from("nonexist")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            // check allow on allids
            let res = be.search(audit, &lim_allow_allids, &filt);
            assert!(res.is_ok());
            let res = be.exists(audit, &lim_allow_allids, &filt);
            assert!(res.is_ok());

            // check deny on allids
            let res = be.search(audit, &lim_deny_allids, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            let res = be.exists(audit, &lim_deny_allids, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
        })
    }

    #[test]
    fn test_be_limits_results_max() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            let mut lim_allow = EventLimits::unlimited();
            lim_allow.search_max_results = usize::MAX;

            let mut lim_deny = EventLimits::unlimited();
            lim_deny.search_max_results = 0;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("userid", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e.add_ava("nonexist", Value::from("x"));
            let e = unsafe { e.into_sealed_new() };
            let single_result = be.create(audit, vec![e.clone()]);
            assert!(single_result.is_ok());

            let filt = unsafe {
                e.filter_from_attrs(&vec![AttrString::from("nonexist")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };

            // --> This is the all ids path (unindexed)
            // check allow on entry max
            let res = be.search(audit, &lim_allow, &filt);
            assert!(res.is_ok());
            let res = be.exists(audit, &lim_allow, &filt);
            assert!(res.is_ok());

            // check deny on entry max
            let res = be.search(audit, &lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(audit, &lim_deny, &filt);
            assert!(res.is_ok());

            // --> This will shortcut due to indexing.
            assert!(be.reindex(audit).is_ok());
            let res = be.search(audit, &lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(audit, &lim_deny, &filt);
            assert!(res.is_ok());
        })
    }

    #[test]
    fn test_be_limits_partial_filter() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
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
            let mut lim_allow = EventLimits::unlimited();
            lim_allow.search_max_filter_test = usize::MAX;

            let mut lim_deny = EventLimits::unlimited();
            lim_deny.search_max_filter_test = 0;

            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava("name", Value::from("william"));
            e.add_ava("uuid", Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e.add_ava("nonexist", Value::from("x"));
            e.add_ava("nonexist", Value::from("y"));
            let e = unsafe { e.into_sealed_new() };
            let single_result = be.create(audit, vec![e.clone()]);
            assert!(single_result.is_ok());

            // Reindex so we have things in place for our query
            assert!(be.reindex(audit).is_ok());

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

            let res = be.search(audit, &lim_allow, &filt);
            assert!(res.is_ok());
            let res = be.exists(audit, &lim_allow, &filt);
            assert!(res.is_ok());

            // check deny on entry max
            let res = be.search(audit, &lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
            // we don't limit on exists because we never load the entries.
            let res = be.exists(audit, &lim_deny, &filt);
            assert!(res == Err(OperationError::ResourceLimit));
        })
    }
}
