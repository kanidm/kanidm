// Attribute uniqueness plugin. We read the schema and determine if the
// value should be unique, and how to handle if it is not. This will
// matter a lot when it comes to replication based on first-wins or
// both change approaches.
//
//
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kanidm_proto::v1::{ConsistencyError, PluginError};
use tracing::trace;

use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::schema::SchemaTransaction;

pub struct AttrUnique;

fn get_cand_attr_set<'a, VALID: 'a, STATE: 'a, T>(
    // cand: &[Entry<VALID, STATE>],
    cand: T,
    uniqueattrs: &[AttrString],
) -> Result<BTreeMap<(AttrString, PartialValue), Vec<Uuid>>, OperationError>
where
    T: IntoIterator<Item = &'a Entry<VALID, STATE>>,
{
    let mut cand_attr: BTreeMap<(AttrString, PartialValue), Vec<Uuid>> = BTreeMap::new();

    cand.into_iter()
        // We don't need to consider recycled or tombstoned entries
        .filter_map(|e| e.mask_recycled_ts())
        .try_for_each(|e| {
            let uuid = e
                .get_ava_single_uuid(Attribute::Uuid)
                .ok_or_else(|| {
                    error!("An entry is missing its uuid. This should be impossible!");
                    OperationError::InvalidEntryState
                })?;

            // Faster to iterate over the attr vec inside this loop.
            for attrstr in uniqueattrs.iter() {
                if let Some(vs) = e.get_ava_set(attrstr.try_into()?) {
                for pv in vs.to_partialvalue_iter() {
                    let key = (attrstr.clone(), pv);
                    cand_attr.entry(key)
                        // Must have conflicted, lets append.
                        .and_modify(|v| {
                            warn!(
                                "ava already exists -> {:?} on entry {:?} has conflicts within change set",
                                attrstr,
                                e.get_display_id()
                            );
                            v.push(uuid)
                        })
                        // Not found, lets setup.
                        .or_insert_with(|| vec![uuid]);
                    }
                }
            }

            Ok(())
        })
        .map(|()| cand_attr)
}

fn enforce_unique<VALID, STATE>(
    qs: &mut QueryServerWriteTransaction,
    cand: &[Entry<VALID, STATE>],
) -> Result<(), OperationError> {
    let uniqueattrs = {
        let schema = qs.get_schema();
        schema.get_attributes_unique()
    };

    // Build a set of all the value -> uuid for the cands.
    // If already exist, reject due to dup.
    let cand_attr_set = get_cand_attr_set(cand, uniqueattrs).map_err(|e| {
        error!(err = ?e, "failed to get cand attr set");
        e
    })?;

    // No candidates to check!
    if cand_attr_set.is_empty() {
        return Ok(());
    }

    // Now we have to identify and error on anything that has multiple items.
    let mut cand_attr = Vec::with_capacity(cand_attr_set.len());
    let mut err = false;
    for (key, mut uuid_set) in cand_attr_set.into_iter() {
        if let Some(uuid) = uuid_set.pop() {
            if uuid_set.is_empty() {
                // Good, only single uuid, this can proceed.
                cand_attr.push((key, uuid));
            } else {
                // Multiple uuid(s) may remain, this is a conflict. We already warned on it
                // before in the processing. Do we need to warn again?
                err = true;
            }
        } else {
            // Corrupt? How did we even get here?
            warn!("datastructure corruption occurred while processing candidate attribute set");
            debug_assert!(false);
            return Err(OperationError::Plugin(PluginError::AttrUnique(
                "corruption detected".to_string(),
            )));
        }
    }

    if err {
        return Err(OperationError::Plugin(PluginError::AttrUnique(
            "duplicate value detected".to_string(),
        )));
    }

    // Now do an internal search on name and !uuid for each
    let mut cand_filters = Vec::new();
    for ((attr, v), uuid) in cand_attr.iter() {
        // and[ attr eq k, andnot [ uuid eq v ]]
        // Basically this says where name but also not self.
        cand_filters.push(f_and(vec![
            FC::Eq(attr, v.clone()),
            f_andnot(FC::Eq(Attribute::Uuid.as_ref(), PartialValue::Uuid(*uuid))),
        ]));
    }

    // Or
    let filt_in = filter!(f_or(cand_filters.clone()));

    trace!(?filt_in);

    // If any results, reject.
    let conflict_cand = qs.internal_exists(filt_in).map_err(|e| {
        admin_error!("internal exists error {:?}", e);
        e
    })?;

    // TODO! Need to make this show what conflicted!
    // We can probably bisect over the filter to work this out?

    if conflict_cand {
        // Some kind of confilct exists. We need to isolate which parts of the filter were suspect.
        // To do this, we bisect over the filter and it's suspect elements.
        //
        // In most cases there is likely only 1 suspect element. But in some there are more. To make
        // this process faster we "bisect" over chunks of the filter remaining until we have only single elements left.
        //
        // We do a bisect rather than a linear one-at-a-time search because we want to try to somewhat minimise calls
        // through internal exists since that has a filter resolve and validate step.

        // Fast-ish path. There is 0 or 1 element, so we just fast return.
        if cand_filters.len() < 2 {
            error!(
                ?cand_filters,
                "The following filter conditions failed to assert uniqueness"
            );
        } else {
            // First iteration, we already failed and we know that, so we just prime and setup two
            // chunks here.

            let mid = cand_filters.len() / 2;
            let (left, right) = cand_filters.split_at(mid);

            let mut queue = VecDeque::new();
            queue.push_back(left);
            queue.push_back(right);

            // Ok! We are setup to go

            while let Some(cand_query) = queue.pop_front() {
                let filt_in = filter!(f_or(cand_query.to_vec()));
                let conflict_cand = qs.internal_search(filt_in).map_err(|e| {
                    admin_error!("internal exists error {:?}", e);
                    e
                })?;

                // A conflict was found!
                if let Some(conflict_cand_zero) = conflict_cand.first() {
                    if cand_query.len() >= 2 {
                        // Continue to split to isolate.
                        let mid = cand_query.len() / 2;
                        let (left, right) = cand_query.split_at(mid);
                        queue.push_back(left);
                        queue.push_back(right);
                        // Continue!
                    } else {
                        // Report this as a failing query.
                        error!(cand_filters = ?cand_query, conflicting_with = %conflict_cand_zero.get_display_id(), "The following filter conditions failed to assert uniqueness");
                    }
                }
            }
            // End logging / warning iterator
        }

        Err(OperationError::Plugin(PluginError::AttrUnique(
            "duplicate value detected".to_string(),
        )))
    } else {
        // If all okay, okay!
        Ok(())
    }
}

impl Plugin for AttrUnique {
    fn id() -> &'static str {
        "plugin_attrunique"
    }

    #[instrument(level = "debug", name = "attrunique_pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        enforce_unique(qs, cand)
    }

    #[instrument(level = "debug", name = "attrunique_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        enforce_unique(qs, cand)
    }

    #[instrument(level = "debug", name = "attrunique_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        enforce_unique(qs, cand)
    }

    #[instrument(level = "debug", name = "attrunique_pre_repl_refresh", skip_all)]
    fn pre_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntryRefreshNew],
    ) -> Result<(), OperationError> {
        enforce_unique(qs, cand)
    }

    #[instrument(level = "debug", name = "attrunique_post_repl_incremental", skip_all)]
    fn post_repl_incremental_conflict(
        qs: &mut QueryServerWriteTransaction,
        cand: &[(EntrySealedCommitted, Arc<EntrySealedCommitted>)],
        conflict_uuids: &mut BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // We need to detect attribute unique violations here. This can *easily* happen in
        // replication since we have two nodes where different entries can modify an attribute
        // and on the next incremental replication the uniqueness violation occurs.
        //
        // Because of this we have some key properties that we can observe.
        //
        // Every node when it makes a change with regard to it's own content is already compliant
        // to attribute uniqueness. This means the consumers db content before we begin is
        // fully consistent.
        //
        // As attributes can be updated multiple times before it is replicated the cid of the
        // attribute may not be a true reflection of order of events when considering which
        // attribute-value should survive/conflict.
        //
        // Attribute uniqueness constraints can *only* be violated on entries that have been
        // replicated or are involved in replication (e.g. a conflict survivor entry).
        //
        // The content of the cand set may contain both replicated entries and conflict survivors
        // that are in the process of being updated. Entries within the cand set *may* be in
        // a conflict state with each other.
        //
        // Since this is a post operation, the content of these cand entries is *also* current
        // in the database.
        //
        // This means that:
        // * We can build a set of attr unique queries from the cand set.
        // * We can ignore conflicts while building that set.
        // * Any conflicts detected in the DB on executing that filter would be a super set of the
        //   conflicts that exist in reality.
        // * All entries that are involved in the attr unique collision must become conflicts.

        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        // Build a set of all the value -> uuid for the cands.
        // If already exist, reject due to dup.
        let cand_attr_set =
            get_cand_attr_set(cand.iter().map(|(e, _)| e), uniqueattrs).map_err(|e| {
                error!(err = ?e, "failed to get cand attr set");
                e
            })?;

        // No candidates to check!
        if cand_attr_set.is_empty() {
            return Ok(());
        }

        // HAPPY FAST PATH - we do the fast existence query and if it passes
        // we can *proceed*, nothing has conflicted.
        let cand_filters: Vec<_> = cand_attr_set
            .iter()
            .flat_map(|((attr, v), uuids)| {
                uuids.iter().map(|uuid| {
                    // and[ attr eq k, andnot [ uuid eq v ]]
                    // Basically this says where name but also not self.
                    f_and(vec![
                        FC::Eq(attr, v.clone()),
                        f_andnot(FC::Eq(Attribute::Uuid.as_ref(), PartialValue::Uuid(*uuid))),
                    ])
                })
            })
            .collect();

        let filt_in = filter!(f_or(cand_filters));

        trace!(?filt_in);

        // If any results, reject.
        let conflict_cand = qs.internal_exists(filt_in).map_err(|e| {
            admin_error!("internal exists error {:?}", e);
            e
        })?;

        if conflict_cand {
            // Unlike enforce unique, we need to be more thorough here. Enforce unique
            // just has to block the whole operation. We *can't* fail the operation
            // in the same way, we need to individually isolate each collision to
            // turn all the involved entries into conflicts. Because of this, rather
            // than bisection like we do in enforce_unique to find violating entries
            // for admins to read, we need to actually isolate each and every conflicting
            // uuid. To achieve this we need to change the structure of the query we perform
            // to actually get everything that has a conflict now.

            // For each uuid, show the set of uuids this conflicts with.
            let mut conflict_uuid_map: BTreeMap<Uuid, BTreeSet<Uuid>> = BTreeMap::new();

            // We need to invert this now to have a set of uuid: Vec<(attr, pv)>
            // rather than the other direction which was optimised for the detection of
            // candidate conflicts during updates.

            let mut cand_attr_map: BTreeMap<Uuid, BTreeSet<_>> = BTreeMap::new();

            cand_attr_set.into_iter().for_each(|(key, uuids)| {
                uuids.into_iter().for_each(|uuid| {
                    cand_attr_map
                        .entry(uuid)
                        .and_modify(|set| {
                            set.insert(key.clone());
                        })
                        .or_insert_with(|| {
                            let mut set = BTreeSet::new();
                            set.insert(key.clone());
                            set
                        });
                })
            });

            for (uuid, ava_set) in cand_attr_map.into_iter() {
                let cand_filters: Vec<_> = ava_set
                    .iter()
                    .map(|(attr, pv)| {
                        f_and(vec![
                            FC::Eq(attr, pv.clone()),
                            f_andnot(FC::Eq(Attribute::Uuid.as_ref(), PartialValue::Uuid(uuid))),
                        ])
                    })
                    .collect();

                let filt_in = filter!(f_or(cand_filters.clone()));

                let filt_conflicts = qs.internal_search(filt_in).map_err(|e| {
                    admin_error!("internal search error {:?}", e);
                    e
                })?;

                // Important! This needs to conflict in *both directions*. We have to
                // indicate that uuid has been conflicted by the entries in filt_conflicts,
                // but also that the entries in filt_conflicts now conflict on us! Also remember
                // that entries in either direction *may already* be in the conflict map, so we
                // need to be very careful here not to stomp anything - append only!
                if !filt_conflicts.is_empty() {
                    let mut conflict_uuid_set = BTreeSet::new();

                    for e in filt_conflicts {
                        // Mark that this entry conflicted to us.
                        conflict_uuid_set.insert(e.get_uuid());
                        // Mark that the entry needs to conflict against us.
                        conflict_uuid_map
                            .entry(e.get_uuid())
                            .and_modify(|set| {
                                set.insert(uuid);
                            })
                            .or_insert_with(|| {
                                let mut set = BTreeSet::new();
                                set.insert(uuid);
                                set
                            });
                    }

                    conflict_uuid_map
                        .entry(uuid)
                        .and_modify(|set| set.append(&mut conflict_uuid_set))
                        .or_insert_with(|| conflict_uuid_set);
                }
            }

            trace!(?conflict_uuid_map);

            if conflict_uuid_map.is_empty() {
                error!("Impossible state. Attribute unique conflicts were detected in fast path, but were not found in slow path.");
                return Err(OperationError::InvalidState);
            }

            // Now get all these values out with modify writable

            let filt = filter!(FC::Or(
                conflict_uuid_map
                    .keys()
                    .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(*u)))
                    .collect()
            ));

            let mut work_set = qs.internal_search_writeable(&filt)?;

            for (_, entry) in work_set.iter_mut() {
                let Some(uuid) = entry.get_uuid() else {
                    error!("Impossible state. Entry that was declared in conflict map does not have a uuid.");
                    return Err(OperationError::InvalidState);
                };

                // Add the uuid to the conflict uuids now.
                conflict_uuids.insert(uuid);

                if let Some(conflict_uuid_set) = conflict_uuid_map.get(&uuid) {
                    entry.to_conflict(conflict_uuid_set.iter().copied())
                } else {
                    error!("Impossible state. Entry that was declared in conflict map was not present in work set.");
                    return Err(OperationError::InvalidState);
                }
            }

            qs.internal_apply_writable(work_set).map_err(|e| {
                admin_error!("Failed to commit memberof group set {:?}", e);
                e
            })?;

            // Okay we *finally got here. We are done!
            Ok(())
        } else {
            // 🎉
            Ok(())
        }
    }

    #[instrument(level = "debug", name = "attrunique::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Only check live entries, not recycled.
        let filt_in = filter!(f_pres(Attribute::Class));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let all_cand: Vec<_> = all_cand.into_iter().map(|e| e.as_ref().clone()).collect();

        let uniqueattrs = {
            let schema = qs.get_schema();
            schema.get_attributes_unique()
        };

        let mut res: Vec<Result<(), ConsistencyError>> = Vec::new();

        if get_cand_attr_set(&all_cand, uniqueattrs).is_err() {
            res.push(Err(ConsistencyError::DuplicateUniqueAttribute))
        }

        trace!(?res);

        res
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::v1::PluginError;

    use crate::prelude::*;

    // Test entry in db, and same name, reject.
    #[test]
    fn test_pre_create_name_unique() {
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let create = vec![e.clone()];
        let preload = vec![e];

        run_create_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "duplicate value detected".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // Test two entries in create that would have same name, reject.
    #[test]
    fn test_pre_create_name_unique_2() {
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let create = vec![e.clone(), e];
        let preload = Vec::new();

        run_create_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "ava already exists".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // Remember, an entry can't have a duplicate value within itself so we don't need to
    // test this case.

    // A mod to something that exists, reject.
    #[test]
    fn test_pre_modify_name_unique() {
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );
        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "duplicate value detected".to_string()
            ))),
            preload,
            filter!(f_or!([f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            ),])),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name.into()),
                Modify::Present(Attribute::Name.into(), Value::new_iname("testgroup_a"))
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Two items modded to have the same value, reject.
    #[test]
    fn test_pre_modify_name_unique_2() {
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );
        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::AttrUnique(
                "ava already exists".to_string()
            ))),
            preload,
            filter!(f_or!([
                f_eq(Attribute::Name, PartialValue::new_iname("testgroup_a")),
                f_eq(Attribute::Name, PartialValue::new_iname("testgroup_b")),
            ])),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name.into()),
                Modify::Present(Attribute::Name.into(), Value::new_iname("testgroup"))
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_verify_name_unique() {
        // Can we preload two dups and verify to show we detect?
    }
}
