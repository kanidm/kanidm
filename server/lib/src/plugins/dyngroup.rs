use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kanidm_proto::internal::Filter as ProtoFilter;

use crate::filter::FilterInvalid;
use crate::prelude::*;
use crate::server::ServerPhase;

#[derive(Clone, Default)]
pub struct DynGroupCache {
    insts: BTreeMap<Uuid, Filter<FilterInvalid>>,
}

pub struct DynGroup;

impl DynGroup {
    /// Determine if any dynamic groups changed as part of this operation.
    #[allow(clippy::too_many_arguments)]
    fn apply_dyngroup_change(
        qs: &mut QueryServerWriteTransaction,
        // The uuids that are affected by the dyngroup change. This is both addition
        // and removal of the uuids as members.
        affected_uuids: &mut BTreeSet<Uuid>,
        // If we should error when a dyngroup we thought should be cached is in fact,
        // not cached.
        expect: bool,
        // The identity in use.
        ident_internal: &Identity,
        // The dyn group cache
        dyn_groups: &mut DynGroupCache,
        // The list of dyn groups that were in the change set
        n_dyn_groups: &[&Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        /*
         * This triggers even if we are modifying the dyngroups account policy attributes, which
         * is allowed now. So we relax this, because systemprotection still blocks the creation
         * of dyngroups.
        if !ident.is_internal() {
            // It should be impossible to trigger this right now due to protected plugin.
            error!("It is currently an error to create a dynamic group");
            return Err(OperationError::SystemProtectedObject);
        }
        */

        if qs.get_phase() < ServerPhase::SchemaReady {
            debug!("Server is not ready to load dyngroups");
            return Ok(());
        }

        // Search all dyn groups that were involved in the operation.
        let filt = filter!(FC::Or(
            n_dyn_groups
                .iter()
                .map(|e| f_eq(Attribute::Uuid, PartialValue::Uuid(e.get_uuid())))
                .collect()
        ));
        // Load the dyn groups as a writeable set.
        let mut work_set = qs.internal_search_writeable(&filt)?;

        // Go through them all and update the groups.
        for (ref pre, ref mut nd_group) in work_set.iter_mut() {
            trace!(dyngroup_id = %nd_group.get_display_id());
            // Load the dyngroups filter
            let scope_f: ProtoFilter = nd_group
                .get_ava_single_protofilter(Attribute::DynGroupFilter)
                .cloned()
                .ok_or_else(|| {
                    error!("Missing {}", Attribute::DynGroupFilter);
                    OperationError::InvalidEntryState
                })?;

            let scope_i = Filter::from_rw(ident_internal, &scope_f, qs).map_err(|e| {
                error!("{} validation failed {:?}", Attribute::DynGroupFilter, e);
                e
            })?;

            trace!(dyngroup_filter = ?scope_i);

            let uuid = pre.get_uuid();
            // Add our uuid as affected.
            affected_uuids.insert(uuid);

            // Apply the filter and get all the uuids that are members of this dyngroup.
            let entries = qs.internal_search(scope_i.clone()).map_err(|e| {
                error!("internal search failure -> {:?}", e);
                e
            })?;

            trace!(entries_len = %entries.len());

            let members = ValueSetRefer::from_iter(entries.iter().map(|e| e.get_uuid()));
            trace!(?members);

            if let Some(uuid_iter) = members.as_ref().and_then(|a| a.as_ref_uuid_iter()) {
                affected_uuids.extend(uuid_iter);
            }

            // Mark the former members as being affected also.
            if let Some(uuid_iter) = pre.get_ava_as_refuuid(Attribute::DynMember) {
                affected_uuids.extend(uuid_iter);
            }

            if let Some(members) = members {
                // Only set something if there is actually something to do!
                nd_group.set_ava_set(Attribute::DynMember, members);
                // push the entries to pre/cand
            } else {
                nd_group.purge_ava(Attribute::DynMember);
            }

            // Insert it to the dyngroup cache with the compiled/resolved filter for
            // fast matching in other paths.
            if dyn_groups.insts.insert(uuid, scope_i).is_none() == expect {
                error!("{} cache uuid conflict {}", Attribute::DynGroup, uuid);
                return Err(OperationError::InvalidState);
            }
        }

        if !work_set.is_empty() {
            qs.internal_apply_writable(work_set).map_err(|e| {
                error!("Failed to commit dyngroup set {:?}", e);
                e
            })?;
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "dyngroup::reload", skip_all)]
    pub fn reload(qs: &mut QueryServerWriteTransaction) -> Result<(), OperationError> {
        let ident_internal = Identity::from_internal();
        // Internal search all our definitions.
        let filt = filter!(f_eq(Attribute::Class, EntryClass::DynGroup.into()));
        let entries = qs.internal_search(filt).map_err(|e| {
            error!("internal search failure -> {:?}", e);
            e
        })?;

        let mut reload_groups = BTreeMap::default();

        for nd_group in entries.into_iter() {
            let scope_f: ProtoFilter = nd_group
                .get_ava_single_protofilter(Attribute::DynGroupFilter)
                .cloned()
                .ok_or_else(|| {
                    error!("Missing {}", Attribute::DynGroupFilter);
                    OperationError::InvalidEntryState
                })?;

            let scope_i = Filter::from_rw(&ident_internal, &scope_f, qs).map_err(|e| {
                error!("dyngroup_filter validation failed {:?}", e);
                e
            })?;

            let uuid = nd_group.get_uuid();

            if reload_groups.insert(uuid, scope_i).is_some() {
                error!("dyngroup cache uuid conflict {}", uuid);
                return Err(OperationError::InvalidState);
            }
        }

        let dyn_groups = qs.get_dyngroup_cache();
        std::mem::swap(&mut reload_groups, &mut dyn_groups.insts);

        Ok(())
    }

    #[instrument(level = "debug", name = "dyngroup::post_create", skip_all)]
    pub fn post_create(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ident: &Identity,
    ) -> Result<BTreeSet<Uuid>, OperationError> {
        let mut affected_uuids = BTreeSet::new();

        let ident_internal = Identity::from_internal();

        let (n_dyn_groups, entries): (Vec<&Entry<_, _>>, Vec<_>) = cand.iter().partition(|entry| {
            entry.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into())
        });

        // DANGER: Why do we have to do this? During the use of qs for internal search
        // and other operations we need qs to be mut. But when we borrow dyn groups here we
        // cause multiple borrows to occur on struct members that freaks rust out. This *IS*
        // safe however because no element of the search or write process calls the dyngroup
        // cache excepting for this plugin within a single thread, meaning that stripping the
        // lifetime here is safe since we are the sole accessor.
        let dyn_groups: &mut DynGroupCache = unsafe { &mut *(qs.get_dyngroup_cache() as *mut _) };

        // For any other entries, check if they SHOULD trigger
        // a dyn group inclusion. We do this FIRST because the new
        // dyn groups will see the created entries on an internal search
        // so we don't need to reference them.

        let mut candidate_tuples = Vec::with_capacity(cand.len());

        // Apply existing dyn_groups to entries.
        trace!(?dyn_groups.insts);
        for (dg_uuid, dg_filter) in dyn_groups.insts.iter() {
            let dg_filter_valid = dg_filter
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)
                .and_then(|f| {
                    f.resolve(&ident_internal, None, Some(qs.get_resolve_filter_cache()))
                })?;

            // Did any of our modified entries match our dyn group filter?
            let matches: Vec<_> = entries
                .iter()
                .filter_map(|e| {
                    if e.entry_match_no_index(&dg_filter_valid) {
                        Some(e.get_uuid())
                    } else {
                        None
                    }
                })
                .collect();

            // If any of them did, we retrieve the dyngroup and setup to write the new
            // members to it.
            if !matches.is_empty() {
                let filt = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(*dg_uuid)));
                let mut work_set = qs.internal_search_writeable(&filt)?;

                if let Some((pre, mut d_group)) = work_set.pop() {
                    matches
                        .iter()
                        .copied()
                        .for_each(|u| d_group.add_ava(Attribute::DynMember, Value::Refer(u)));

                    affected_uuids.extend(matches.into_iter());
                    affected_uuids.insert(*dg_uuid);

                    candidate_tuples.push((pre, d_group));
                }
            }
        }

        // Write back the new changes.
        // Write this stripe if populated.
        if !candidate_tuples.is_empty() {
            qs.internal_apply_writable(candidate_tuples).map_err(|e| {
                error!("Failed to commit dyngroup set {:?}", e);
                e
            })?;
        }

        // If we created any dyn groups, populate them now.
        //    if the event is not internal, reject (for now)

        if !n_dyn_groups.is_empty() {
            trace!("considering new dyngroups");
            Self::apply_dyngroup_change(
                qs,
                &mut affected_uuids,
                false,
                &ident_internal,
                dyn_groups,
                n_dyn_groups.as_slice(),
            )?;
        }

        Ok(affected_uuids)
    }

    #[instrument(level = "debug", name = "dyngroup::post_modify", skip_all)]
    pub fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ident: &Identity,
        force_cand_updates: bool,
    ) -> Result<BTreeSet<Uuid>, OperationError> {
        let mut affected_uuids = BTreeSet::new();

        let ident_internal = Identity::from_internal();

        // Probably should be filter here instead.
        let (_, pre_entries): (Vec<&Arc<Entry<_, _>>>, Vec<_>) =
            pre_cand.iter().partition(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into())
            });

        let (n_dyn_groups, post_entries): (Vec<&Entry<_, _>>, Vec<_>) =
            cand.iter().partition(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into())
            });

        // DANGER: Why do we have to do this? During the use of qs for internal search
        // and other operations we need qs to be mut. But when we borrow dyn groups here we
        // cause multiple borrows to occur on struct members that freaks rust out. This *IS*
        // safe however because no element of the search or write process calls the dyngroup
        // cache excepting for this plugin within a single thread, meaning that stripping the
        // lifetime here is safe since we are the sole accessor.
        let dyn_groups: &mut DynGroupCache = unsafe { &mut *(qs.get_dyngroup_cache() as *mut _) };

        let mut candidate_tuples = Vec::with_capacity(dyn_groups.insts.len() + cand.len());

        // If we modified a dyngroups member or filter, re-trigger it here.
        //    if the event is not internal, reject (for now)
        // We do this *first* so that we don't accidentally include/exclude anything that
        // changed in this op.

        if !n_dyn_groups.is_empty() {
            Self::apply_dyngroup_change(
                qs,
                &mut affected_uuids,
                true,
                &ident_internal,
                dyn_groups,
                n_dyn_groups.as_slice(),
            )?;
        }

        // If we modified anything else, check if a dyngroup is affected by it's change
        // if it was a member.
        trace!(?force_cand_updates, ?dyn_groups.insts);

        for (dg_uuid, dg_filter) in dyn_groups.insts.iter() {
            let dg_filter_valid = dg_filter
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)
                .and_then(|f| {
                    f.resolve(&ident_internal, None, Some(qs.get_resolve_filter_cache()))
                })?;

            let matches: Vec<_> = pre_entries
                .iter()
                .zip(post_entries.iter())
                .filter_map(|(pre, post)| {
                    let pre_t = pre.entry_match_no_index(&dg_filter_valid);
                    let post_t = post.entry_match_no_index(&dg_filter_valid);

                    trace!(?post_t, ?force_cand_updates, ?pre_t);

                    // There are some cases where rather than the optimisation to skip
                    // asserting membership, we need to always assert that membership. Generally
                    // this occurs in replication where if a candidate was conflicted it can
                    // trigger a membership delete, but we need to ensure it's still re-added.
                    if post_t && (force_cand_updates || !pre_t) {
                        // The entry was added
                        Some(Ok(post.get_uuid()))
                    } else if pre_t && !post_t {
                        // The entry was deleted
                        Some(Err(post.get_uuid()))
                    } else {
                        None
                    }
                })
                .collect();

            trace!(?matches);

            if !matches.is_empty() {
                let filt = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(*dg_uuid)));
                let mut work_set = qs.internal_search_writeable(&filt)?;

                if let Some((pre, mut d_group)) = work_set.pop() {
                    matches.iter().copied().for_each(|choice| match choice {
                        Ok(u) => d_group.add_ava(Attribute::DynMember, Value::Refer(u)),
                        Err(u) => d_group.remove_ava(Attribute::DynMember, &PartialValue::Refer(u)),
                    });

                    affected_uuids.extend(matches.into_iter().map(|choice| match choice {
                        Ok(u) => u,
                        Err(u) => u,
                    }));
                    affected_uuids.insert(*dg_uuid);

                    candidate_tuples.push((pre, d_group));
                }
            }
        }

        // Write back the new changes.
        // Write this stripe if populated.
        trace!(candidate_tuples_len = %candidate_tuples.len());
        if !candidate_tuples.is_empty() {
            qs.internal_apply_writable(candidate_tuples).map_err(|e| {
                error!("Failed to commit dyngroup set {:?}", e);
                e
            })?;
        }

        trace!(?affected_uuids);

        Ok(affected_uuids)
    }

    // No post_delete handler is needed as refint takes care of this for us.

    pub fn verify(_qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::internal::Filter as ProtoFilter;

    use crate::prelude::*;

    const UUID_TEST_GROUP: Uuid = uuid::uuid!("7bfd9931-06c2-4608-8a46-78719bb746fe");

    #[test]
    fn test_create_dyngroup_add_new_group() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_group];
        let create = vec![e_dyn];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_matching_entry() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn];
        let create = vec![e_group];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_non_matching_entry() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "no_possible_match_to_be_found".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn];
        let create = vec![e_group];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set(Attribute::DynMember).is_none());
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_matching_entry_and_group() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![];
        let create = vec![e_dyn, e_group];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
                assert!(d_group.get_ava_set(Attribute::Member).is_none());
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_filter_into_scope() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "no_such_entry_exists".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_dyngroup")
            )),
            ModifyList::new_list(vec![
                Modify::Purged("dyngroup_filter".into()),
                Modify::Present(
                    Attribute::DynGroupFilter.into(),
                    Value::JsonFilt(ProtoFilter::Eq(
                        Attribute::Name.to_string(),
                        "testgroup".to_string()
                    ))
                )
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_filter_outof_scope() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_dyngroup")
            )),
            ModifyList::new_list(vec![
                Modify::Purged("dyngroup_filter".into()),
                Modify::Present(
                    Attribute::DynGroupFilter.into(),
                    Value::JsonFilt(ProtoFilter::Eq(
                        Attribute::Name.to_string(),
                        "no_such_entry_exists".to_string()
                    ))
                )
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set(Attribute::DynMember).is_none());
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_member_add() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_dyngroup")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::DynMember.into(),
                Value::Refer(UUID_ADMIN)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");
                // We assert to refer single here because we should have "removed" uuid_admin being added
                // at all.
                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_member_remove() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_dyngroup")
            )),
            ModifyList::new_list(vec![Modify::Purged(Attribute::DynMember.into(),)]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");
                // We assert to refer single here because we should have re-added the members
                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_into_matching_entry() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("not_testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("not_testgroup")
            )),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name.into(),),
                Modify::Present(Attribute::Name.into(), Value::new_iname("testgroup"))
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set(Attribute::DynMember)
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_into_non_matching_entry() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testgroup"))),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name.into(),),
                Modify::Present(Attribute::Name.into(), Value::new_iname("not_testgroup"))
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set(Attribute::DynMember).is_none());
            }
        );
    }

    #[test]
    fn test_delete_dyngroup_matching_entry() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testgroup"))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set(Attribute::DynMember).is_none());
            }
        );
    }

    #[test]
    fn test_delete_dyngroup_group() {
        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_dyngroup")
            )),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                // Note we check memberof is empty here!
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set(Attribute::MemberOf).is_none());
            }
        );
    }
}
