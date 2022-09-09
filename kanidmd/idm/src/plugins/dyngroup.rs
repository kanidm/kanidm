use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::filter::FilterInvalid;
use crate::prelude::*;
use kanidm_proto::v1::Filter as ProtoFilter;
use std::collections::BTreeMap;
use std::sync::Arc;

lazy_static! {
    static ref CLASS_DYNGROUP: PartialValue = PartialValue::new_class("dyngroup");
}

#[derive(Clone)]
pub struct DynGroupCache {
    insts: BTreeMap<Uuid, Filter<FilterInvalid>>,
}

impl Default for DynGroupCache {
    fn default() -> Self {
        DynGroupCache {
            insts: BTreeMap::default(),
        }
    }
}

pub struct DynGroup;

impl DynGroup {
    #[instrument(level = "debug", name = "dyngroup_post_create", skip(qs, cand, ce))]
    pub fn post_create(
        qs: &QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ce: &CreateEvent,
    ) -> Result<Vec<Uuid>, OperationError> {
        let mut affected_uuids = Vec::with_capacity(cand.len());

        let ident_internal = Identity::from_internal();

        let (n_dyn_groups, entries): (Vec<&Entry<_, _>>, Vec<_>) = cand
            .iter()
            .partition(|entry| entry.attribute_equality("class", &CLASS_DYNGROUP));

        let dyn_groups = qs.get_dyngroup_cache();

        // For any other entries, check if they SHOULD trigger
        // a dyn group inclusion. We do this FIRST because the new
        // dyn groups will see the created entries on an internal search
        // so we don't need to reference them.

        //
        let resolve_filter_cache = qs.get_resolve_filter_cache();

        let mut pre_candidates = Vec::with_capacity(dyn_groups.insts.len() + cand.len());
        let mut candidates = Vec::with_capacity(dyn_groups.insts.len() + cand.len());

        trace!(?dyn_groups.insts);

        for (dg_uuid, dg_filter) in dyn_groups.insts.iter() {
            let dg_filter_valid = dg_filter
                .validate(qs.get_schema())
                .map_err(OperationError::SchemaViolation)
                .and_then(|f| {
                    f.resolve(&ident_internal, None, Some(resolve_filter_cache))
                })?;

            let matches: Vec<_> = entries.iter()
                .filter_map(|e| {
                    if e.entry_match_no_index(&dg_filter_valid) {
                        Some(e.get_uuid())
                    } else {
                        None
                    }
                })
                .collect();

            if !matches.is_empty() {
                let filt = filter!(f_eq("uuid", PartialValue::new_uuid(*dg_uuid)));
                let mut work_set = qs.internal_search_writeable(&filt)?;

                if let Some((pre, mut d_group)) = work_set.pop() {

                    matches.iter().copied().for_each(|u| {
                        d_group.add_ava("member", Value::new_refer(u))
                    });

                    affected_uuids.extend(matches.into_iter());
                    affected_uuids.push(*dg_uuid);

                    pre_candidates.push(pre);
                    candidates.push(d_group);
                }
            }
        }

        // If we created any dyn groups, populate them now.
        //    if the event is not internal, reject (for now)

        if !n_dyn_groups.is_empty() {
            trace!("considering new dyngroups");

            if !ce.ident.is_internal() {
                // It should be impossible to trigger this right now due to protected plugin.
                error!("It is currently an error to create a dynamic group");
                return Err(OperationError::SystemProtectedObject);
            }

            // Search all the new groups first.
            let filt = filter!(FC::Or(
                n_dyn_groups
                    .into_iter()
                    .map(|e| f_eq("uuid", PartialValue::new_uuid(e.get_uuid())))
                    .collect()
            ));
            let work_set = qs.internal_search_writeable(&filt)?;

            // Go through them all and update the new groups.
            for (pre, mut nd_group) in work_set.into_iter() {
                let scope_f: ProtoFilter = nd_group
                    .get_ava_single_protofilter("dyngroup_filter")
                    .cloned()
                    .ok_or_else(|| {
                        admin_error!("Missing dyngroup_filter");
                        OperationError::InvalidEntryState
                    })?;
                let scope_i = Filter::from_rw(&ident_internal, &scope_f, qs).map_err(|e| {
                    admin_error!("dyngroup_filter validation failed {:?}", e);
                    e
                })?;

                let uuid = pre.get_uuid();
                // Add our uuid as affected.
                affected_uuids.push(uuid);

                // Apply the filter and get all the uuids.
                let entries = qs.internal_search(scope_i.clone()).map_err(|e| {
                    admin_error!("internal search failure -> {:?}", e);
                    e
                })?;

                let members = ValueSetRefer::from_iter(entries.iter().map(|e| e.get_uuid()));

                if let Some(uuid_iter) = members.as_ref().and_then(|a| a.as_ref_uuid_iter()) {
                    affected_uuids.extend(uuid_iter);
                }

                if let Some(members) = members {
                    // Only set something if there is actually something to do!
                    nd_group.set_ava_set("member", members);
                    // push the entries to pre/cand
                    pre_candidates.push(pre);
                    candidates.push(nd_group);
                }

                // Insert to our new instances
                if dyn_groups.insts.insert(uuid, scope_i).is_some() {
                    admin_error!("dyngroup cache already contains uuid {}", uuid);
                    return Err(OperationError::InvalidState);
                }
            }

        }

        // Write back the new changes.
        debug_assert!(pre_candidates.len() == candidates.len());
        // Write this stripe if populated.
        if !pre_candidates.is_empty() {
            qs.internal_batch_modify(pre_candidates, candidates)
                .map_err(|e| {
                    admin_error!("Failed to commit dyngroup set {:?}", e);
                    e
                })?;
        }

        Ok(affected_uuids)
    }

    #[instrument(
        level = "debug",
        name = "memberof_post_modify",
        skip(_qs, _pre_cand, _cand, _me)
    )]
    pub fn post_modify(
        _qs: &QueryServerWriteTransaction,
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        _cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &ModifyEvent,
    ) -> Result<Vec<Uuid>, OperationError> {
        // If we modified a dyngroups member or filter, re-trigger it here.
        //    if the event is not internal, reject (for now)

        // If we modified anything else, check if a dyngroup is affected by it's change
        // if it was a member.

        Ok(Vec::new())
    }

    // No post_delete handler is needed as refint takes care of this for us.

    pub fn verify(_qs: &QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use kanidm_proto::v1::Filter as ProtoFilter;

    const UUID_TEST_GROUP: Uuid = uuid::uuid!("7bfd9931-06c2-4608-8a46-78719bb746fe");

    #[test]
    fn test_create_dyngroup_add_new_group() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_group];
        let create = vec![e_dyn];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_matching_entry() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn];
        let create = vec![e_group];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_non_matching_entry() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq(
                    "name".to_string(),
                    "no_possible_match_to_be_found".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn];
        let create = vec![e_group];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set("member").is_none());
            }
        );
    }

    #[test]
    fn test_create_dyngroup_add_matching_entry_and_group() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![];
        let create = vec![e_dyn, e_group];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            // Need to validate it did things
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_filter_into_scope() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq(
                    "name".to_string(),
                    "no_such_entry_exists".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("test_dyngroup"))),
            ModifyList::new_list(vec![
                Modify::Purged("dyngroup_filter".into()),
                Modify::Present(
                    AttrString::from("dyngroup_filter"),
                    Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
                )
            ]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_filter_outof_scope() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("test_dyngroup"))),
            ModifyList::new_list(vec![
                Modify::Purged("dyngroup_filter".into()),
                Modify::Present(
                    AttrString::from("dyngroup_filter"),
                    Value::JsonFilt(ProtoFilter::Eq(
                        "name".to_string(),
                        "no_such_entry_exists".to_string()
                    ))
                )
            ]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set("member").is_none());
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_existing_dyngroup_member_add() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("test_dyngroup"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
                Value::new_uuid(*UUID_ADMIN)
            )]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
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
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("test_dyngroup"))),
            ModifyList::new_list(vec![Modify::Purged(AttrString::from("member"),)]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
                    .expect("No members on dyn group");
                // We assert to refer single here because we should have re-added the members
                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_into_matching_entry() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("not_testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("not_testgroup"))),
            ModifyList::new_list(vec![
                Modify::Purged(AttrString::from("name"),),
                Modify::Present(AttrString::from("name"), Value::new_iname("testgroup"))
            ]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                let members = d_group
                    .get_ava_set("member")
                    .expect("No members on dyn group");

                assert!(members.to_refer_single() == Some(UUID_TEST_GROUP));
            }
        );
    }

    #[test]
    fn test_modify_dyngroup_into_non_matching_entry() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testgroup"))),
            ModifyList::new_list(vec![
                Modify::Purged(AttrString::from("name"),),
                Modify::Present(AttrString::from("name"), Value::new_iname("not_testgroup"))
            ]),
            None,
            |_| {},
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set("member").is_none());
            }
        );
    }

    #[test]
    fn test_delete_dyngroup_matching_entry() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testgroup"))),
            None,
            |qs: &QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "name",
                        PartialValue::new_iname("test_dyngroup")
                    )))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set("member").is_none());
            }
        );
    }

    #[test]
    fn test_delete_dyngroup_group() {
        let e_dyn = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("group")),
            ("class", Value::new_class("dyngroup")),
            ("name", Value::new_iname("test_dyngroup")),
            (
                "dyngroup_filter",
                Value::JsonFilt(ProtoFilter::Eq("name".to_string(), "testgroup".to_string()))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            ("uuid", Value::new_uuid(UUID_TEST_GROUP))
        );

        let preload = vec![e_dyn, e_group];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("test_dyngroup"))),
            None,
            |qs: &QueryServerWriteTransaction| {
                // Note we check memberof is empty here!
                let cands = qs
                    .internal_search(filter!(f_eq("name", PartialValue::new_iname("testgroup"))))
                    .expect("Internal search failure");

                let d_group = cands.get(0).expect("Unable to access group.");
                assert!(d_group.get_ava_set("memberof").is_none());
            }
        );
    }
}
