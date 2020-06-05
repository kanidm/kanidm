use std::convert::TryFrom;
use std::fs;

use crate::value::IndexType;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::audit::AuditScope;
use crate::be::dbentry::DbEntry;
use crate::entry::{Entry, EntryCommitted, EntryNew, EntrySealed};
use crate::filter::{Filter, FilterPlan, FilterResolved, FilterValidResolved};
use idlset::AndNot;
use idlset::IDLBitRange;
use kanidm_proto::v1::{ConsistencyError, OperationError};
use uuid::Uuid;

pub mod dbentry;
pub mod dbvalue;
mod idl_arc_sqlite;
mod idl_sqlite;

use crate::be::idl_arc_sqlite::{
    IdlArcSqlite, IdlArcSqliteReadTransaction, IdlArcSqliteTransaction,
    IdlArcSqliteWriteTransaction,
};

const FILTER_SEARCH_TEST_THRESHOLD: usize = 8;
const FILTER_EXISTS_TEST_THRESHOLD: usize = 0;

#[derive(Debug, Clone)]
pub enum IDL {
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

#[derive(Clone)]
pub struct Backend {
    idlayer: Arc<IdlArcSqlite>,
}

pub struct BackendReadTransaction<'a> {
    idlayer: IdlArcSqliteReadTransaction<'a>,
}

pub struct BackendWriteTransaction<'a> {
    idxmeta: BTreeSet<(String, IndexType)>,
    // idxcache: IdxCache,
    idlayer: IdlArcSqliteWriteTransaction<'a>,
}

impl IdRawEntry {
    fn into_entry(self) -> Result<Entry<EntrySealed, EntryCommitted>, OperationError> {
        let db_e = serde_cbor::from_slice(self.data.as_slice())
            .map_err(|_| OperationError::SerdeCborError)?;
        let id = u64::try_from(self.id).map_err(|_| OperationError::InvalidEntryID)?;
        Entry::from_dbentry(db_e, id).map_err(|_| OperationError::CorruptedEntry(id))
    }
}

pub trait BackendTransaction {
    type IdlLayerType: IdlArcSqliteTransaction;
    fn get_idlayer(&mut self) -> &mut Self::IdlLayerType;

    /// Recursively apply a filter, transforming into IDL's on the way. This builds a query
    /// execution log, so that it can be examined how an operation proceeded.
    fn filter2idl(
        &mut self,
        au: &mut AuditScope,
        filt: &FilterResolved,
        thres: usize,
    ) -> Result<(IDL, FilterPlan), OperationError> {
        let fr = Ok(match filt {
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
                            IDL::Indexed(idl),
                            FilterPlan::EqIndexed(attr.to_string(), idx_key),
                        ),
                        None => (IDL::ALLIDS, FilterPlan::EqCorrupt(attr.to_string())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IDL::ALLIDS, FilterPlan::EqUnindexed(attr.to_string()))
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
                            IDL::Indexed(idl),
                            FilterPlan::SubIndexed(attr.to_string(), idx_key),
                        ),
                        None => (IDL::ALLIDS, FilterPlan::SubCorrupt(attr.to_string())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IDL::ALLIDS, FilterPlan::SubUnindexed(attr.to_string()))
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
                        Some(idl) => (IDL::Indexed(idl), FilterPlan::PresIndexed(attr.to_string())),
                        None => (IDL::ALLIDS, FilterPlan::PresCorrupt(attr.to_string())),
                    }
                } else {
                    // Schema believes this is not indexed
                    (IDL::ALLIDS, FilterPlan::PresUnindexed(attr.to_string()))
                }
            }
            FilterResolved::LessThan(attr, _subvalue, _idx) => {
                // We have no process for indexing this right now.
                (IDL::ALLIDS, FilterPlan::LessThanUnindexed(attr.to_string()))
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
                        (IDL::Indexed(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                        }
                        (IDL::Partial(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                            partial = true;
                        }
                        (IDL::PartialThreshold(idl), fp) => {
                            plan.push(fp);
                            // now union them (if possible)
                            result = result | idl;
                            partial = true;
                            threshold = true;
                        }
                        (IDL::ALLIDS, fp) => {
                            plan.push(fp);
                            // If we find anything unindexed, the whole term is unindexed.
                            lfilter_error!(au, "Term {:?} is ALLIDS, shortcut return", f);
                            let setplan = FilterPlan::OrUnindexed(plan);
                            return Ok((IDL::ALLIDS, setplan));
                        }
                    }
                } // end or.iter()
                  // If we got here, every term must have been indexed or partial indexed.
                if partial {
                    if threshold {
                        let setplan = FilterPlan::OrPartialThreshold(plan);
                        (IDL::PartialThreshold(result), setplan)
                    } else {
                        let setplan = FilterPlan::OrPartial(plan);
                        (IDL::Partial(result), setplan)
                    }
                } else {
                    let setplan = FilterPlan::OrIndexed(plan);
                    (IDL::Indexed(result), setplan)
                }
            }
            FilterResolved::And(l) => {
                // This algorithm is a little annoying. I couldn't get it to work with iter and
                // folds due to the logic needed ...

                // First, setup the two filter lists. We always apply AndNot after positive
                // and terms.
                let (f_andnot, f_rem): (Vec<_>, Vec<_>) = l.iter().partition(|f| f.is_andnot());

                // We make this an iter, so everything comes off in order. Using pop means we
                // pull from the tail, which is the WORST item to start with!
                let mut f_rem_iter = f_rem.iter();

                // Setup the initial result.
                let (mut cand_idl, fp) = match f_rem_iter.next() {
                    Some(f) => self.filter2idl(au, f, thres)?,
                    None => {
                        lfilter_error!(au, "WARNING: And filter was empty, or contains only AndNot, can not evaluate.");
                        return Ok((IDL::Indexed(IDLBitRange::new()), FilterPlan::Invalid));
                    }
                };

                // Setup the query plan tracker
                let mut plan = Vec::new();
                plan.push(fp);

                match &cand_idl {
                    IDL::Indexed(idl) | IDL::Partial(idl) | IDL::PartialThreshold(idl) => {
                        // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                        // But we only do this when there are actually multiple elements in the and,
                        // because an and with 1 element now is FULLY resolved.
                        if idl.len() < thres && f_rem.len() > 0 {
                            lfilter_warning!(
                                au,
                                "NOTICE: Cand set shorter than threshold, early return"
                            );
                            let setplan = FilterPlan::AndPartialThreshold(plan);
                            return Ok((IDL::PartialThreshold(idl.clone()), setplan));
                        } else if idl.len() == 0 {
                            // Regardless of the input state, if it's empty, this can never
                            // be satisfied, so return we are indexed and complete.
                            lfilter_warning!(
                                au,
                                "NOTICE: empty candidate set, shortcutting return."
                            );
                            let setplan = FilterPlan::AndEmptyCand(plan);
                            return Ok((IDL::Indexed(IDLBitRange::new()), setplan));
                        }
                    }
                    IDL::ALLIDS => {}
                }

                // Now, for all remaining,
                for f in f_rem_iter {
                    let (inter, fp) = self.filter2idl(au, f, thres)?;
                    plan.push(fp);
                    cand_idl = match (cand_idl, inter) {
                        (IDL::Indexed(ia), IDL::Indexed(ib)) => {
                            let r = ia & ib;
                            if r.len() < thres {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                lfilter_warning!(
                                    au,
                                    "NOTICE: Cand set shorter than threshold, early return"
                                );
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IDL::PartialThreshold(r), setplan));
                            } else if r.len() == 0 {
                                // Regardless of the input state, if it's empty, this can never
                                // be satisfied, so return we are indexed and complete.
                                lfilter_warning!(
                                    au,
                                    "NOTICE: empty candidate set, shortcutting return."
                                );
                                let setplan = FilterPlan::AndEmptyCand(plan);
                                return Ok((IDL::Indexed(IDLBitRange::new()), setplan));
                            } else {
                                IDL::Indexed(r)
                            }
                        }
                        (IDL::Indexed(ia), IDL::Partial(ib))
                        | (IDL::Partial(ia), IDL::Indexed(ib))
                        | (IDL::Partial(ia), IDL::Partial(ib)) => {
                            let r = ia & ib;
                            if r.len() < thres {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                lfilter_warning!(
                                    au,
                                    "NOTICE: Cand set shorter than threshold, early return"
                                );
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IDL::PartialThreshold(r), setplan));
                            } else {
                                IDL::Partial(r)
                            }
                        }
                        (IDL::Indexed(ia), IDL::PartialThreshold(ib))
                        | (IDL::PartialThreshold(ia), IDL::Indexed(ib))
                        | (IDL::PartialThreshold(ia), IDL::PartialThreshold(ib))
                        | (IDL::PartialThreshold(ia), IDL::Partial(ib))
                        | (IDL::Partial(ia), IDL::PartialThreshold(ib)) => {
                            let r = ia & ib;
                            if r.len() < thres {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                lfilter_warning!(
                                    au,
                                    "NOTICE: Cand set shorter than threshold, early return"
                                );
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IDL::PartialThreshold(r), setplan));
                            } else {
                                IDL::PartialThreshold(r)
                            }
                        }
                        (IDL::Indexed(i), IDL::ALLIDS)
                        | (IDL::ALLIDS, IDL::Indexed(i))
                        | (IDL::Partial(i), IDL::ALLIDS)
                        | (IDL::ALLIDS, IDL::Partial(i)) => IDL::Partial(i),
                        (IDL::PartialThreshold(i), IDL::ALLIDS)
                        | (IDL::ALLIDS, IDL::PartialThreshold(i)) => IDL::PartialThreshold(i),
                        (IDL::ALLIDS, IDL::ALLIDS) => IDL::ALLIDS,
                    };
                }

                // debug!("partial cand set ==> {:?}", cand_idl);

                for f in f_andnot.iter() {
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
                        (IDL::Indexed(ia), IDL::Indexed(ib)) => {
                            let r = ia.andnot(ib);
                            /*
                            // Don't trigger threshold on and nots if fully indexed.
                            if r.len() < thres {
                                // When below thres, we have to return partials to trigger the entry_no_match_filter check.
                                lfilter_warning!(au, "NOTICE: Cand set shorter than threshold, early return");
                                return Ok(IDL::PartialThreshold(r));
                            } else {
                                IDL::Indexed(r)
                            }
                            */
                            IDL::Indexed(r)
                        }
                        (IDL::Indexed(ia), IDL::Partial(ib))
                        | (IDL::Partial(ia), IDL::Indexed(ib))
                        | (IDL::Partial(ia), IDL::Partial(ib)) => {
                            let r = ia.andnot(ib);
                            // DO trigger threshold on partials, because we have to apply the filter
                            // test anyway, so we may as well shortcut at this point.
                            if r.len() < thres {
                                lfilter_warning!(
                                    au,
                                    "NOTICE: Cand set shorter than threshold, early return"
                                );
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IDL::PartialThreshold(r), setplan));
                            } else {
                                IDL::Partial(r)
                            }
                        }
                        (IDL::Indexed(ia), IDL::PartialThreshold(ib))
                        | (IDL::PartialThreshold(ia), IDL::Indexed(ib))
                        | (IDL::PartialThreshold(ia), IDL::PartialThreshold(ib))
                        | (IDL::PartialThreshold(ia), IDL::Partial(ib))
                        | (IDL::Partial(ia), IDL::PartialThreshold(ib)) => {
                            let r = ia.andnot(ib);
                            // DO trigger threshold on partials, because we have to apply the filter
                            // test anyway, so we may as well shortcut at this point.
                            if r.len() < thres {
                                lfilter_warning!(
                                    au,
                                    "NOTICE: Cand set shorter than threshold, early return"
                                );
                                let setplan = FilterPlan::AndPartialThreshold(plan);
                                return Ok((IDL::PartialThreshold(r), setplan));
                            } else {
                                IDL::PartialThreshold(r)
                            }
                        }

                        (IDL::Indexed(_), IDL::ALLIDS)
                        | (IDL::ALLIDS, IDL::Indexed(_))
                        | (IDL::Partial(_), IDL::ALLIDS)
                        | (IDL::ALLIDS, IDL::Partial(_))
                        | (IDL::PartialThreshold(_), IDL::ALLIDS)
                        | (IDL::ALLIDS, IDL::PartialThreshold(_)) => {
                            // We could actually generate allids here
                            // and then try to reduce the and-not set, but
                            // for now we just return all ids.
                            IDL::ALLIDS
                        }
                        (IDL::ALLIDS, IDL::ALLIDS) => IDL::ALLIDS,
                    };
                }

                // What state is the final cand idl in?
                let setplan = match cand_idl {
                    IDL::Indexed(_) => FilterPlan::AndIndexed(plan),
                    IDL::Partial(_) | IDL::PartialThreshold(_) => FilterPlan::AndPartial(plan),
                    IDL::ALLIDS => FilterPlan::AndUnindexed(plan),
                };

                // Finally, return the result.
                // debug!("final cand set ==> {:?}", cand_idl);
                (cand_idl, setplan)
            } // end and
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
                (IDL::Indexed(IDLBitRange::new()), FilterPlan::Invalid)
            }
        });
        // debug!("result of {:?} -> {:?}", filt, fr);
        fr
    }

    // Take filter, and AuditScope ref?
    fn search(
        &mut self,
        au: &mut AuditScope,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        //
        // Unlike DS, even if we don't get the index back, we can just pass
        // to the in-memory filter test and be done.
        lperf_segment!(au, "be::search", || {
            // Do a final optimise of the filter
            lfilter!(au, "filter unoptimised form --> {:?}", filt);
            let filt = filt.optimise();
            lfilter!(au, "filter optimised to --> {:?}", filt);

            // Using the indexes, resolve the IDL here, or ALLIDS.
            // Also get if the filter was 100% resolved or not.
            let (idl, fplan) = lperf_segment!(au, "be::search -> filter2idl", || {
                self.filter2idl(au, filt.to_inner(), FILTER_SEARCH_TEST_THRESHOLD)
            })?;

            lfilter!(au, "filter executed plan -> {:?}", fplan);

            let entries = try_audit!(au, self.get_idlayer().get_identry(au, &idl));
            // Do other things
            // Now, de-serialise the raw_entries back to entries, and populate their ID's

            // if not 100% resolved.

            let entries_filtered = match idl {
                IDL::ALLIDS | IDL::Partial(_) => {
                    lfilter_error!(
                        au,
                        "filter (search) was partially or fully unindexed. {:?}",
                        filt
                    );
                    entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(&filt))
                        .collect()
                }
                IDL::PartialThreshold(_) => {
                    lfilter_warning!(
                        au,
                        "filter (search) was partial unindexed due to test threshold {:?}",
                        filt
                    );
                    entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(&filt))
                        .collect()
                }
                // Since the index fully resolved, we can shortcut the filter test step here!
                IDL::Indexed(_) => {
                    lfilter!(au, "filter (search) was fully indexed 👏");
                    entries
                }
            };

            /*
             // This is good for testing disagreements between the idl layer and the filter/entries
            if cfg!(test) {
                let check_raw_entries = try_audit!(au, self.get_idlayer().get_identry(au, &IDL::ALLIDS));
                let check_entries: Result<Vec<_>, _> =
                    check_raw_entries.into_iter().map(|ide| ide.into_entry()).collect();
                let check_entries = try_audit!(au, check_entries);
                let f_check_entries: Vec<_> =
                    check_entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(&filt))
                        .collect();
                debug!("raw   -> {:?}", entries_filtered);
                debug!("check -> {:?}", f_check_entries);
                assert!(f_check_entries == entries_filtered);
            }
            */

            Ok(entries_filtered)
        })
    }

    /// Given a filter, assert some condition exists.
    /// Basically, this is a specialised case of search, where we don't need to
    /// load any candidates if they match. This is heavily used in uuid
    /// refint and attr uniqueness.
    fn exists(
        &mut self,
        au: &mut AuditScope,
        filt: &Filter<FilterValidResolved>,
    ) -> Result<bool, OperationError> {
        lperf_segment!(au, "be::exists", || {
            // Do a final optimise of the filter
            lfilter!(au, "filter unoptimised form --> {:?}", filt);
            let filt = filt.optimise();
            lfilter!(au, "filter optimised to --> {:?}", filt);

            // Using the indexes, resolve the IDL here, or ALLIDS.
            // Also get if the filter was 100% resolved or not.
            let (idl, fplan) = lperf_segment!(au, "be::exists -> filter2idl", || {
                self.filter2idl(au, filt.to_inner(), FILTER_EXISTS_TEST_THRESHOLD)
            })?;

            lfilter!(au, "filter executed plan -> {:?}", fplan);

            // Now, check the idl -- if it's fully resolved, we can skip this because the query
            // was fully indexed.
            match &idl {
                IDL::Indexed(idl) => {
                    lfilter!(au, "filter (exists) was fully indexed 👏");
                    Ok(idl.len() > 0)
                }
                IDL::PartialThreshold(_) => {
                    lfilter_warning!(
                        au,
                        "filter (exists) was partial unindexed due to test threshold {:?}",
                        filt
                    );
                    let entries = try_audit!(au, self.get_idlayer().get_identry(au, &idl));

                    // if not 100% resolved query, apply the filter test.
                    let entries_filtered: Vec<_> = entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(&filt))
                        .collect();

                    Ok(!entries_filtered.is_empty())
                }
                _ => {
                    lfilter_error!(
                        au,
                        "filter (exists) was partially or fully unindexed {:?}",
                        filt
                    );
                    let entries = try_audit!(au, self.get_idlayer().get_identry(au, &idl));

                    // if not 100% resolved query, apply the filter test.
                    let entries_filtered: Vec<_> = entries
                        .into_iter()
                        .filter(|e| e.entry_match_no_index(&filt))
                        .collect();

                    Ok(!entries_filtered.is_empty())
                }
            } // end match idl
        }) // end audit segment
    }

    fn verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        // Vec::new()
        self.get_idlayer().verify()
    }

    fn backup(&mut self, audit: &mut AuditScope, dst_path: &str) -> Result<(), OperationError> {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let idl = IDL::ALLIDS;
        let raw_entries: Vec<IdRawEntry> = self.get_idlayer().get_identry_raw(audit, &idl)?;

        let entries: Result<Vec<DbEntry>, _> = raw_entries
            .iter()
            .map(|id_ent| {
                serde_cbor::from_slice(id_ent.data.as_slice())
                    .map_err(|_| OperationError::SerdeJsonError)
            })
            .collect();

        let entries = entries?;

        let serialized_entries = serde_json::to_string_pretty(&entries);

        let serialized_entries_str = try_audit!(
            audit,
            serialized_entries,
            "serde error {:?}",
            OperationError::SerdeJsonError
        );

        let result = fs::write(dst_path, serialized_entries_str);

        try_audit!(
            audit,
            result,
            "fs::write error {:?}",
            OperationError::FsError
        );

        Ok(())
    }
}

impl<'a> BackendTransaction for BackendReadTransaction<'a> {
    type IdlLayerType = IdlArcSqliteReadTransaction<'a>;

    fn get_idlayer(&mut self) -> &mut IdlArcSqliteReadTransaction<'a> {
        &mut self.idlayer
    }
}

impl<'a> BackendTransaction for BackendWriteTransaction<'a> {
    type IdlLayerType = IdlArcSqliteWriteTransaction<'a>;

    fn get_idlayer(&mut self) -> &mut IdlArcSqliteWriteTransaction<'a> {
        &mut self.idlayer
    }
}

impl<'a> BackendWriteTransaction<'a> {
    pub fn create(
        &mut self,
        au: &mut AuditScope,
        entries: Vec<Entry<EntrySealed, EntryNew>>,
    ) -> Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> {
        lperf_segment!(au, "be::create", || {
            if entries.is_empty() {
                ladmin_error!(
                    au,
                    "No entries provided to BE to create, invalid server call!"
                );
                return Err(OperationError::EmptyRequest);
            }

            // Now, assign id's to all the new entries.

            let mut id_max = self.idlayer.get_id2entry_max_id().and_then(|id_max| {
                u64::try_from(id_max).map_err(|_| OperationError::InvalidEntryID)
            })?;
            let c_entries: Vec<_> = entries
                .into_iter()
                .map(|e| {
                    id_max += 1;
                    e.into_sealed_committed_id(id_max)
                })
                .collect();

            self.idlayer.write_identries(au, c_entries.iter())?;

            // Now update the indexes as required.
            for e in c_entries.iter() {
                self.entry_index(au, None, Some(e))?
            }

            Ok(c_entries)
        })
    }

    pub fn modify(
        &mut self,
        au: &mut AuditScope,
        pre_entries: &[Entry<EntrySealed, EntryCommitted>],
        post_entries: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        lperf_segment!(au, "be::modify", || {
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
                        .map_err(|_| OperationError::InvalidEntryID)
                        .and_then(|id| {
                            if id == 0 {
                                Err(OperationError::InvalidEntryID)
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
            self.idlayer.write_identries(au, post_entries.iter())?;

            // Finally, we now reindex all the changed entries. We do this by iterating and zipping
            // over the set, because we know the list is in the same order.
            pre_entries
                .iter()
                .zip(post_entries.iter())
                .try_for_each(|(pre, post)| self.entry_index(au, Some(pre), Some(post)))
        })
    }

    pub fn delete(
        &mut self,
        au: &mut AuditScope,
        entries: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        lperf_segment!(au, "be::delete", || {
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
            self.idlayer.delete_identry(au, id_list)?;

            // Finally, purge the indexes from the entries we removed.
            entries
                .iter()
                .try_for_each(|e| self.entry_index(au, Some(e), None))
        })
    }

    // Should take a mut index set, and then we write the whole thing back
    // in a single stripe.
    //
    // So we need a cache, which we load indexes into as we do ops, then we
    // modify them.
    //
    // At the end, we flush those cchange outs in a single run.
    // For create this is probably a
    fn entry_index(
        &mut self,
        audit: &mut AuditScope,
        pre: Option<&Entry<EntrySealed, EntryCommitted>>,
        post: Option<&Entry<EntrySealed, EntryCommitted>>,
    ) -> Result<(), OperationError> {
        let e_id = match (pre, post) {
            (None, None) => {
                ltrace!(audit, "Invalid call to entry_index - no entries provided");
                return Err(OperationError::InvalidState);
            }
            (Some(pre), None) => {
                ltrace!(audit, "Attempting to remove indexes");
                pre.get_id()
            }
            (None, Some(post)) => {
                ltrace!(audit, "Attempting to update indexes");
                post.get_id()
            }
            (Some(pre), Some(post)) => {
                ltrace!(audit, "Attempting to modify indexes");
                assert!(pre.get_id() == post.get_id());
                post.get_id()
            }
        };

        // Extremely Cursed - Okay, we know that self.idxmeta will NOT be changed
        // in this function, but we need to borrow self as mut for the caches in
        // get_idl to work. As a result, this causes a double borrow. To work around
        // this we discard the lifetime on idxmeta, because we know that it will
        // remain constant for the life of the operation.

        let idxmeta = unsafe { &(*(&self.idxmeta as *const _)) };

        let idx_diff = Entry::idx_diff(&idxmeta, pre, post);

        idx_diff.iter()
            .try_for_each(|act| {
                match act {
                    Ok((attr, itype, idx_key)) => {
                        ltrace!(audit, "Adding {:?} idx -> {:?}: {:?}", itype, attr, idx_key);
                        match self.idlayer.get_idl(audit, attr, itype, idx_key)? {
                            Some(mut idl) => {
                                idl.insert_id(e_id);
                                self.idlayer.write_idl(audit, attr, itype, idx_key, &idl)
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
                        match self.idlayer.get_idl(audit, attr, itype, idx_key)? {
                            Some(mut idl) => {
                                idl.remove_id(e_id);
                                self.idlayer.write_idl(audit, attr, itype, idx_key, &idl)
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
        &mut self,
        audit: &mut AuditScope,
    ) -> Result<Vec<(String, IndexType)>, OperationError> {
        let idx_table_list = self.idlayer.list_idxs(audit)?;

        // Turn the vec to a real set
        let idx_table_set: BTreeSet<_> = idx_table_list.into_iter().collect();

        let missing: Vec<_> = self
            .idxmeta
            .iter()
            .filter_map(|(attr, itype)| {
                // what would the table name be?
                let tname = format!("idx_{}_{}", itype.as_idx_str(), attr);
                ltrace!(audit, "Checking for {}", tname);

                if idx_table_set.contains(&tname) {
                    None
                } else {
                    Some((attr.clone(), itype.clone()))
                }
            })
            .collect();
        Ok(missing)
    }

    fn create_idxs(&self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // Create name2uuid and uuid2name
        ltrace!(audit, "Creating index -> name2uuid");
        self.idlayer.create_name2uuid(audit)?;

        ltrace!(audit, "Creating index -> uuid2name");
        self.idlayer.create_uuid2name(audit)?;

        self.idxmeta
            .iter()
            .try_for_each(|(attr, itype)| self.idlayer.create_idx(audit, attr, itype))
    }

    pub fn upgrade_reindex(
        &mut self,
        audit: &mut AuditScope,
        v: i64,
    ) -> Result<(), OperationError> {
        if self.get_db_index_version() < v {
            self.reindex(audit)?;
        }
        self.set_db_index_version(v)
    }

    pub fn reindex(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        // Purge the idxs
        unsafe { self.idlayer.purge_idxs(audit)? };

        // Using the index metadata on the txn, create all our idx tables
        self.create_idxs(audit)?;

        // Now, we need to iterate over everything in id2entry and index them
        // Future idea: Do this in batches of X amount to limit memory
        // consumption.
        let idl = IDL::ALLIDS;
        let entries = try_audit!(audit, self.idlayer.get_identry(audit, &idl));

        // WHEN do we update name2uuid and uuid2name?
        // Do they become attrs of the idx_cache? Should that be a struct?
        try_audit!(
            audit,
            entries
                .iter()
                .try_for_each(|e| self.entry_index(audit, None, Some(e)))
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn purge_idxs(&mut self, audit: &mut AuditScope) -> Result<(), OperationError> {
        unsafe { self.idlayer.purge_idxs(audit) }
    }

    #[cfg(test)]
    pub fn load_test_idl(
        &mut self,
        audit: &mut AuditScope,
        attr: &String,
        itype: &IndexType,
        idx_key: &String,
    ) -> Result<Option<IDLBitRange>, OperationError> {
        self.idlayer.get_idl(audit, attr, itype, idx_key)
    }

    pub fn restore(
        &mut self,
        audit: &mut AuditScope,
        src_path: &str,
    ) -> Result<(), OperationError> {
        // load all entries into RAM, may need to change this later
        // if the size of the database compared to RAM is an issue
        let serialized_string_option = fs::read_to_string(src_path);

        let serialized_string = try_audit!(
            audit,
            serialized_string_option,
            "fs::read_to_string {:?}",
            OperationError::FsError
        );

        try_audit!(audit, unsafe { self.idlayer.purge_id2entry(audit) });

        let dbentries_option: Result<Vec<DbEntry>, serde_json::Error> =
            serde_json::from_str(&serialized_string);

        let dbentries = try_audit!(
            audit,
            dbentries_option,
            "serde_json error {:?}",
            OperationError::SerdeJsonError
        );

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

        self.idlayer
            .write_identries_raw(audit, identries?.into_iter())?;

        // for debug
        /*
        self.idlayer.get_identry(audit, &IDL::ALLIDS)
            .unwrap()
            .iter()
            .for_each(|dbe| {
                ltrace!(audit, "dbe -> {:?}", dbe.id);
            });
        */

        // Reindex now we are loaded.
        self.reindex(audit)?;

        let vr = self.verify();
        if vr.is_empty() {
            Ok(())
        } else {
            Err(OperationError::ConsistencyError(vr))
        }
    }

    pub fn commit(self, audit: &mut AuditScope) -> Result<(), OperationError> {
        self.idlayer.commit(audit)
    }

    fn reset_db_s_uuid(&self) -> Result<Uuid, OperationError> {
        // The value is missing. Generate a new one and store it.
        let nsid = Uuid::new_v4();
        self.idlayer.write_db_s_uuid(nsid)?;
        Ok(nsid)
    }

    pub fn get_db_s_uuid(&mut self) -> Uuid {
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
        self.idlayer.write_db_d_uuid(nsid)?;
        Ok(nsid)
    }

    pub fn get_db_d_uuid(&mut self) -> Uuid {
        match self
            .get_idlayer()
            .get_db_d_uuid()
            .expect("DBLayer Error!!!")
        {
            Some(d_uuid) => d_uuid,
            None => self.reset_db_d_uuid().expect("Failed to regenerate D_UUID"),
        }
    }

    fn get_db_index_version(&mut self) -> i64 {
        self.get_idlayer().get_db_index_version()
    }

    fn set_db_index_version(&mut self, v: i64) -> Result<(), OperationError> {
        self.get_idlayer().set_db_index_version(v)
    }
}

// In the future this will do the routing between the chosen backends etc.
impl Backend {
    pub fn new(audit: &mut AuditScope, path: &str, pool_size: u32) -> Result<Self, OperationError> {
        // this has a ::memory() type, but will path == "" work?
        lperf_segment!(audit, "be::new", || {
            let be = Backend {
                idlayer: Arc::new(IdlArcSqlite::new(audit, path, pool_size)?),
            };

            // Now complete our setup with a txn
            // In this case we can use an empty idx meta because we don't
            // access any parts of
            // the indexing subsystem here.
            let r = {
                let idl_write = be.idlayer.write();
                idl_write.setup(audit).and_then(|_| idl_write.commit(audit))
            };

            ltrace!(audit, "be new setup: {:?}", r);

            match r {
                Ok(_) => Ok(be),
                Err(e) => Err(e),
            }
        })
    }

    pub fn read(&self) -> BackendReadTransaction {
        BackendReadTransaction {
            idlayer: self.idlayer.read(),
        }
    }

    pub fn write(&self, idxmeta: BTreeSet<(String, IndexType)>) -> BackendWriteTransaction {
        BackendWriteTransaction {
            idlayer: self.idlayer.write(),
            idxmeta,
        }
    }

    // Should this actually call the idlayer directly?
    pub fn reset_db_s_uuid(&self, audit: &mut AuditScope) -> Uuid {
        let wr = self.write(BTreeSet::new());
        let sid = wr.reset_db_s_uuid().unwrap();
        wr.commit(audit).unwrap();
        sid
    }

    /*
    pub fn get_db_s_uuid(&self) -> Uuid {
        let wr = self.write(BTreeSet::new());
        wr.reset_db_s_uuid().unwrap()
    }
    */
}

// What are the possible actions we'll recieve here?

#[cfg(test)]
mod tests {

    use idlset::IDLBitRange;
    use std::collections::BTreeSet;
    use std::fs;
    use std::iter::FromIterator;

    use super::super::audit::AuditScope;
    use super::super::entry::{Entry, EntryInit, EntryNew};
    use super::{Backend, BackendTransaction, BackendWriteTransaction, OperationError, IDL};
    use crate::value::{IndexType, PartialValue, Value};

    macro_rules! run_test {
        ($test_fn:expr) => {{
            use env_logger;
            ::std::env::set_var("RUST_LOG", "kanidm=debug");
            let _ = env_logger::builder()
                .format_timestamp(None)
                .format_level(false)
                .is_test(true)
                .try_init();

            let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4());

            let be = Backend::new(&mut audit, "", 1).expect("Failed to setup backend");

            // This is a demo idxmeta, purely for testing.
            let mut idxmeta = BTreeSet::new();
            idxmeta.insert(("name".to_string(), IndexType::EQUALITY));
            idxmeta.insert(("name".to_string(), IndexType::PRESENCE));
            idxmeta.insert(("name".to_string(), IndexType::SUBSTRING));
            idxmeta.insert(("uuid".to_string(), IndexType::EQUALITY));
            idxmeta.insert(("uuid".to_string(), IndexType::PRESENCE));
            idxmeta.insert(("ta".to_string(), IndexType::EQUALITY));
            idxmeta.insert(("tb".to_string(), IndexType::EQUALITY));
            let mut be_txn = be.write(idxmeta);

            // Could wrap another future here for the future::ok bit...
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
                ei.filter_from_attrs(&vec![String::from("userid")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            let entries = $be.search($audit, &filt).expect("failed to search");
            entries.first().is_some()
        }};
    }

    macro_rules! entry_attr_pres {
        ($audit:expr, $be:expr, $ent:expr, $attr:expr) => {{
            let ei = unsafe { $ent.clone().into_sealed_committed() };
            let filt = unsafe {
                ei.filter_from_attrs(&vec![String::from("userid")])
                    .expect("failed to generate filter")
                    .into_valid_resolved()
            };
            let entries = $be.search($audit, &filt).expect("failed to search");
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
                .expect("IDL Load failed");
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
            e.add_ava("userid", &Value::from("william"));
            e.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
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
            e.add_ava("userid", &Value::from("claire"));
            e.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e = unsafe { e.into_sealed_new() };

            let single_result = be.create(audit, vec![e.clone()]);
            assert!(single_result.is_ok());
            // Test a simple EQ search

            let filt =
                unsafe { filter_resolved!(f_eq("userid", PartialValue::new_utf8s("claire"))) };

            let r = be.search(audit, &filt);
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
            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", &Value::from("alice"));
            e2.add_ava("uuid", &Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };

            assert!(be.create(audit, vec![ve1, ve2]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(audit, unsafe { &filter_resolved!(f_pres("userid")) })
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
            r1.add_ava("desc", &Value::from("modified"));
            r2.add_ava("desc", &Value::from("modified"));

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

            // First create some entries (3?)
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("userid", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", &Value::from("alice"));
            e2.add_ava("uuid", &Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", &Value::from("lucy"));
            e3.add_ava("uuid", &Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));

            let ve1 = unsafe { e1.clone().into_sealed_new() };
            let ve2 = unsafe { e2.clone().into_sealed_new() };
            let ve3 = unsafe { e3.clone().into_sealed_new() };

            assert!(be.create(audit, vec![ve1, ve2, ve3]).is_ok());
            assert!(entry_exists!(audit, be, e1));
            assert!(entry_exists!(audit, be, e2));
            assert!(entry_exists!(audit, be, e3));

            // You need to now retrieve the entries back out to get the entry id's
            let mut results = be
                .search(audit, unsafe { &filter_resolved!(f_pres("userid")) })
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
            e4.add_ava("userid", &Value::from("amy"));
            e4.add_ava("uuid", &Value::from("21d816b5-1f6a-4696-b7c1-6ed06d22ed81"));

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
            e1.add_ava("userid", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("userid", &Value::from("alice"));
            e2.add_ava("uuid", &Value::from("4b6228ab-1dbe-42a4-a9f5-f6368222438e"));

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", &Value::from("lucy"));
            e3.add_ava("uuid", &Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));

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
            // TODO: Test reindex duplicate eq?
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", &Value::from("claire"));
            e2.add_ava("uuid", &Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"));
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
            // check uuid2name
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
            e1.add_ava("name", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
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
            e1.add_ava("name", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", &Value::from("claire"));
            e2.add_ava("uuid", &Value::from("bd651620-00dd-426b-aaa0-4494f7b7906f"));
            let e2 = unsafe { e2.into_sealed_new() };

            let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
            e3.add_ava("userid", &Value::from("lucy"));
            e3.add_ava("uuid", &Value::from("7b23c99d-c06b-4a9a-a958-3afa56383e1d"));
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
            e1.add_ava("name", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("ta", &Value::from("test"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(audit, vec![e1.clone()]).unwrap();
            // Now, alter the new entry.
            let mut ce1 = unsafe { rset[0].clone().into_invalid() };
            // add something.
            ce1.add_ava("tb", &Value::from("test"));
            // remove something.
            ce1.purge_ava("ta");
            // mod something.
            ce1.purge_ava("name");
            ce1.add_ava("name", &Value::from("claire"));

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
            e1.add_ava("name", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            let e1 = unsafe { e1.into_sealed_new() };

            let rset = be.create(audit, vec![e1.clone()]).unwrap();
            // Now, alter the new entry.
            let mut ce1 = unsafe { rset[0].clone().into_invalid() };
            ce1.purge_ava("name");
            ce1.purge_ava("uuid");
            ce1.add_ava("name", &Value::from("claire"));
            ce1.add_ava("uuid", &Value::from("04091a7a-6ce4-42d2-abf5-c2ce244ac9e8"));
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
        })
    }

    #[test]
    fn test_be_index_search_simple() {
        run_test!(|audit: &mut AuditScope, be: &mut BackendWriteTransaction| {
            assert!(be.reindex(audit).is_ok());

            // Create a test entry with some indexed / unindexed values.
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava("name", &Value::from("william"));
            e1.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d1"));
            e1.add_ava("no-index", &Value::from("william"));
            e1.add_ava("other-no-index", &Value::from("william"));
            let e1 = unsafe { e1.into_sealed_new() };

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava("name", &Value::from("claire"));
            e2.add_ava("uuid", &Value::from("db237e8a-0079-4b8c-8a56-593b22aa44d2"));
            let e2 = unsafe { e2.into_sealed_new() };

            let _rset = be.create(audit, vec![e1.clone(), e2.clone()]).unwrap();
            // Test fully unindexed
            let f_un =
                unsafe { filter_resolved!(f_eq("no-index", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(audit, f_un.to_inner(), 0).unwrap();
            match r {
                IDL::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }

            // Test that a fully indexed search works
            let f_eq =
                unsafe { filter_resolved!(f_eq("name", PartialValue::new_utf8s("william"))) };

            let (r, _plan) = be.filter2idl(audit, f_eq.to_inner(), 0).unwrap();
            match r {
                IDL::Indexed(idl) => {
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
                IDL::Indexed(idl) => {
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
                IDL::Partial(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![1]));
                }
                _ => {
                    panic!("");
                }
            }

            let (r, _plan) = be.filter2idl(audit, f_p2.to_inner(), 0).unwrap();
            match r {
                IDL::Partial(idl) => {
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
                IDL::ALLIDS => {}
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
                IDL::Indexed(idl) => {
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
                IDL::ALLIDS => {}
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
                IDL::Indexed(idl) => {
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
                IDL::Indexed(idl) => {
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
                IDL::Indexed(idl) => {
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
                IDL::Indexed(idl) => {
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
                IDL::Indexed(idl) => {
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
                IDL::ALLIDS => {}
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
                IDL::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }

            //   empty or
            let f_e_or = unsafe { filter_resolved!(f_or!([])) };

            let (r, _plan) = be.filter2idl(audit, f_e_or.to_inner(), 0).unwrap();
            match r {
                IDL::Indexed(idl) => {
                    assert!(idl == IDLBitRange::from_iter(vec![]));
                }
                _ => {
                    panic!("");
                }
            }

            let f_e_and = unsafe { filter_resolved!(f_and!([])) };

            let (r, _plan) = be.filter2idl(audit, f_e_and.to_inner(), 0).unwrap();
            match r {
                IDL::Indexed(idl) => {
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
                IDL::ALLIDS => {}
                _ => {
                    panic!("");
                }
            }
        })
    }
}
