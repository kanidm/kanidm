// Referential Integrity
//
// Given an entry, modification or change, ensure that all referential links
// in the database are maintained. IE there are no dangling references that
// are unable to be resolved, as this may cause errors in Item -> ProtoItem
// translation.
//
// It will be important to understand the interaction of this plugin with memberof
// when that is written, as they *both* manipulate and alter entry reference
// data, so we should be careful not to step on each other.

use std::collections::BTreeSet;
use std::sync::Arc;

use hashbrown::HashSet;
use kanidm_proto::v1::ConsistencyError;

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::filter::{f_eq, FC};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::schema::SchemaTransaction;

pub struct ReferentialIntegrity;

impl ReferentialIntegrity {
    fn check_uuids_exist_fast(
        qs: &mut QueryServerWriteTransaction,
        inner: &[Uuid],
    ) -> Result<bool, OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            trace!("no reference types modified, skipping check");
            return Ok(true);
        }

        let inner: Vec<_> = inner
            .iter()
            .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(*u)))
            .collect();

        // F_inc(lusion). All items of inner must be 1 or more, or the filter
        // will fail. This will return the union of the inclusion after the
        // operationn.
        let filt_in = filter!(f_inc(inner));
        let b = qs.internal_exists(filt_in).map_err(|e| {
            admin_error!(err = ?e, "internal exists failure");
            e
        })?;

        // Is the existence of all id's confirmed?
        if b {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn check_uuids_exist_slow(
        qs: &mut QueryServerWriteTransaction,
        inner: &[Uuid],
    ) -> Result<Vec<Uuid>, OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            // Should be unreachable.
            trace!("no reference types modified, skipping check");
            return Ok(Vec::with_capacity(0));
        }

        let mut missing = Vec::with_capacity(inner.len());
        for u in inner {
            let filt_in = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(*u)));
            let b = qs.internal_exists(filt_in).map_err(|e| {
                admin_error!(err = ?e, "internal exists failure");
                e
            })?;

            // If it's missing, we push it to the missing set.
            if !b {
                missing.push(*u)
            }
        }

        Ok(missing)
    }

    fn remove_references(
        qs: &mut QueryServerWriteTransaction,
        uuids: Vec<Uuid>,
    ) -> Result<(), OperationError> {
        trace!(?uuids);

        // Find all reference types in the schema
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let removed_ids: BTreeSet<_> = uuids.iter().map(|u| PartialValue::Refer(*u)).collect();

        // Generate a filter which is the set of all schema reference types
        // as EQ to all uuid of all entries in delete. - this INCLUDES recycled
        // types too!
        let filt = filter_all!(FC::Or(
            uuids
                .into_iter()
                .flat_map(|u| ref_types.values().filter_map(move |r_type| {
                    let value_attribute = r_type.name.to_string();
                    // For everything that references the uuid's in the deleted set.
                    let val: Result<Attribute, OperationError> = value_attribute.try_into();
                    // error!("{:?}", val);
                    let res = match val {
                        Ok(val) => {
                            let res = f_eq(val, PartialValue::Refer(u));
                            Some(res)
                        }
                        Err(err) => {
                            // we shouldn't be able to get here...
                            admin_error!("post_delete invalid attribute specified - please log this as a bug! {:?}", err);
                            None
                        }
                    };
                    res
                }))
                .collect(),
        ));

        trace!("refint post_delete filter {:?}", filt);

        let mut work_set = qs.internal_search_writeable(&filt)?;

        for (_, post) in work_set.iter_mut() {
            for schema_attribute in ref_types.values() {
                let attribute = (&schema_attribute.name).try_into()?;
                post.remove_avas(attribute, &removed_ids);
            }
        }

        qs.internal_apply_writable(work_set)
    }
}

impl Plugin for ReferentialIntegrity {
    fn id() -> &'static str {
        "referential_integrity"
    }

    // Why are these checks all in post?
    //
    // There is a situation to account for which is that a create or mod
    // may introduce the entry which is also to be referenced in the same
    // transaction. Rather than have separate verification paths - one to
    // check the UUID is in the cand set, and one to check the UUID exists
    // in the DB, we do the "correct" thing, write to the DB, and then assert
    // that the DB content is complete and valid instead.
    //
    // Yes, this does mean we do more work to add/index/rollback in an error
    // condition, *but* it means we only have developed a single verification
    // so we can assert stronger trust in it's correct operation and interaction
    // in complex scenarioes - It actually simplifies the check from "could
    // be in cand AND db" to simply "is it in the DB?".
    #[instrument(level = "debug", name = "refint_post_create", skip(qs, cand, _ce))]
    fn post_create(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "refint_post_modify", skip_all)]
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "refint_post_batch_modify", skip_all)]
    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "refint_post_repl_refresh", skip_all)]
    fn post_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "refint_post_repl_incremental", skip_all)]
    fn post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // I think we need to check that all values in the ref type values here
        // exist, and if not, we *need to remove them*. We should probably rewrite
        // how we do modify/create inner to actually return missing uuids, so that
        // this fn can delete, and the other parts can report what's missing.
        //
        // This also becomes a path to a "ref int fixup" too?

        let uuids = Self::cand_references_to_uuid_filter(qs, cand)?;

        let all_exist_fast = Self::check_uuids_exist_fast(qs, uuids.as_slice())?;

        let mut missing_uuids = if !all_exist_fast {
            debug!("Not all uuids referenced by these candidates exist. Slow path to remove them.");
            Self::check_uuids_exist_slow(qs, uuids.as_slice())?
        } else {
            debug!("All references are valid!");
            Vec::with_capacity(0)
        };

        // If the entry has moved from a live to a deleted state we need to clean it's reference's
        // that *may* have been added on this server - the same that other references would be
        // deleted.
        let inactive_entries: Vec<_> = std::iter::zip(pre_cand, cand)
            .filter_map(|(pre, post)| {
                let pre_live = pre.mask_recycled_ts().is_some();
                let post_live = post.mask_recycled_ts().is_some();

                if !post_live && (pre_live != post_live) {
                    // We have moved from live to recycled/tombstoned. We need to
                    // ensure that these references are masked.
                    Some(post.get_uuid())
                } else {
                    None
                }
            })
            .collect();

        if event_enabled!(tracing::Level::DEBUG) {
            debug!("Removing the following reference uuids for entries that have become recycled or tombstoned");
            for missing in &inactive_entries {
                debug!(?missing);
            }
        }

        // We can now combine this with the conflict uuids from the incoming set.

        // In a conflict case, we need to also add these uuids to the delete logic
        // since on the originator node the original uuid will still persist
        // meaning the member won't be removed.
        // However, on a non-primary conflict handler it will remove the member
        // as well. This is annoyingly a worst case, since then *every* node will
        // attempt to update the cid of this group. But I think the potential cost
        // in the short term will be worth consistent references.

        if !conflict_uuids.is_empty() {
            warn!("conflict uuids have been found, and must be cleaned from existing references. This is to prevent group memberships leaking to un-intended recipients.");
        }

        // Now, we need to find for each of the missing uuids, which values had them.
        // We could use a clever query to internal_search_writeable?
        missing_uuids.extend(conflict_uuids.iter().copied());
        missing_uuids.extend_from_slice(&inactive_entries);

        if missing_uuids.is_empty() {
            trace!("Nothing to do, shortcut");
            return Ok(());
        }

        if event_enabled!(tracing::Level::DEBUG) {
            debug!("Removing the following missing reference uuids");
            for missing in &missing_uuids {
                debug!(?missing);
            }
        }

        // Now we have to look them up and clean it up. Turns out this is the
        // same code path as "post delete" so we can share that!
        Self::remove_references(qs, missing_uuids)

        // Complete!
    }

    #[instrument(level = "debug", name = "refint_post_delete", skip_all)]
    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Delete is pretty different to the other pre checks. This is
        // actually the bulk of the work we'll do to clean up references
        // when they are deleted.

        // Get the UUID of all entries we are deleting
        let uuids: Vec<Uuid> = cand.iter().map(|e| e.get_uuid()).collect();

        Self::remove_references(qs, uuids)
    }

    #[instrument(level = "debug", name = "refint::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Get all entries as cand
        //      build a cand-uuid set
        let filt_in = filter_all!(f_pres(Attribute::Class));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let acu_map: HashSet<Uuid> = all_cand.iter().map(|e| e.get_uuid()).collect();

        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let mut res = Vec::new();
        // For all cands
        for c in &all_cand {
            // For all reference in each cand.
            for rtype in ref_types.values() {
                let attr: Attribute = match (&rtype.name).try_into() {
                    Ok(val) => val,
                    Err(err) => {
                        // we shouldn't be able to get here...
                        admin_error!("verify referential integrity invalid attribute {} specified - please log this as a bug! {:?}", &rtype.name, err);
                        res.push(Err(ConsistencyError::InvalidAttributeType(
                            rtype.name.to_string(),
                        )));
                        continue;
                    }
                };
                // If the attribute is present
                if let Some(vs) = c.get_ava_set(attr) {
                    // For each value in the set.
                    match vs.as_ref_uuid_iter() {
                        Some(uuid_iter) => {
                            for vu in uuid_iter {
                                if acu_map.get(&vu).is_none() {
                                    res.push(Err(ConsistencyError::RefintNotUpheld(c.get_id())))
                                }
                            }
                        }
                        None => res.push(Err(ConsistencyError::InvalidAttributeType(
                            "A non-value-ref type was found.".to_string(),
                        ))),
                    }
                }
            }
        }

        res
    }
}

impl ReferentialIntegrity {
    fn cand_references_to_uuid_filter(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntrySealedCommitted],
    ) -> Result<Vec<Uuid>, OperationError> {
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        // Fast Path
        let mut vsiter = cand.iter().flat_map(|c| {
            // If it's dyngroup, skip member since this will be reset in the next step.
            let dyn_group = c.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into());

            ref_types.values().filter_map(move |rtype| {
                // Skip dynamic members, these are recalculated by the
                // memberof plugin.
                let skip_mb = dyn_group && rtype.name == Attribute::DynMember.as_ref();
                // Skip memberOf, also recalculated.
                let skip_mo = rtype.name == Attribute::MemberOf.as_ref();
                if skip_mb || skip_mo {
                    None
                } else {
                    trace!(rtype_name = ?rtype.name, "examining");
                    c.get_ava_set(
                        (&rtype.name)
                            .try_into()
                            .map_err(|e| {
                                admin_error!(?e, "invalid attribute type {}", &rtype.name);
                                None::<Attribute>
                            })
                            .ok()?,
                    )
                }
            })
        });

        // Could check len first?
        let mut i = Vec::with_capacity(cand.len() * 4);
        let mut dedup = HashSet::new();

        vsiter.try_for_each(|vs| {
            if let Some(uuid_iter) = vs.as_ref_uuid_iter() {
                uuid_iter.for_each(|u| {
                    // Returns true if the item is NEW in the set
                    if dedup.insert(u) {
                        i.push(u)
                    }
                });
                Ok(())
            } else {
                admin_error!(?vs, "reference value could not convert to reference uuid.");
                admin_error!("If you are sure the name/uuid/spn exist, and that this is in error, you should run a verify task.");
                Err(OperationError::InvalidAttribute(
                    "uuid could not become reference value".to_string(),
                ))
            }
        })?;

        Ok(i)
    }

    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        let uuids = Self::cand_references_to_uuid_filter(qs, cand)?;

        let all_exist_fast = Self::check_uuids_exist_fast(qs, uuids.as_slice())?;

        if all_exist_fast {
            // All good!
            return Ok(());
        }

        // Okay taking the slow path now ...
        let missing_uuids = Self::check_uuids_exist_slow(qs, uuids.as_slice())?;

        error!("some uuids that were referenced in this operation do not exist.");
        for missing in missing_uuids {
            error!(?missing);
        }

        Err(OperationError::Plugin(
            kanidm_proto::v1::PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string(),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::v1::Filter as ProtoFilter;
    use kanidm_proto::v1::PluginError;

    use crate::event::CreateEvent;
    use crate::prelude::*;
    use crate::value::{Oauth2Session, Session, SessionState};
    use time::OffsetDateTime;
    use uuid::uuid;

    use crate::credential::Credential;
    use kanidm_lib_crypto::CryptoPolicy;

    // The create references a uuid that doesn't exist - reject
    #[test]
    fn test_create_uuid_reference_not_exist() {
        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "description": ["testperson"],
                "member": ["ca85168c-91b7-49a8-b7bb-a3d5bb40e97e"]
            }
        }"#,
        );

        let create = vec![e];
        let preload = Vec::new();
        run_create_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // The create references a uuid that does exist - validate
    #[test]
    fn test_create_uuid_reference_exist() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![ea];
        let create = vec![eb];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup_b")
                    )))
                    .expect("Internal search failure");
                let _ue = cands.first().expect("No cand");
            }
        );
    }

    // The create references itself - allow
    #[test]
    fn test_create_uuid_reference_self() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::new();

        let e: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup"],
                "description": ["testgroup"],
                "uuid": ["8cef42bc-2cac-43e4-96b3-8f54561885ca"],
                "member": ["8cef42bc-2cac-43e4-96b3-8f54561885ca"]
            }
        }"#,
        );

        let create = vec![e];

        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup")
                    )))
                    .expect("Internal search failure");
                let _ue = cands.first().expect("No cand");
            }
        );
    }

    // Modify references a different object - allow
    #[test]
    fn test_modify_uuid_reference_exist() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Modify reference something that doesn't exist - must be rejected
    #[test]
    fn test_modify_uuid_reference_not_exist() {
        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Check that even when SOME references exist, so long as one does not,
    // we fail.
    #[test]
    fn test_modify_uuid_reference_partial_not_exist() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![
                Modify::Present(
                    Attribute::Member.into(),
                    Value::Refer(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                ),
                Modify::Present(Attribute::Member.into(), Value::Refer(UUID_DOES_NOT_EXIST)),
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Modify removes the reference to an entry
    #[test]
    fn test_modify_remove_referee() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Purged(Attribute::Member.into())]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Modify adds reference to self - allow
    #[test]
    fn test_modify_uuid_reference_self() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_a")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Test that deleted entries can not be referenced
    #[test]
    fn test_modify_reference_deleted() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                // Any pre_hooks we need. In this case, we need to trigger the delete of testgroup_a
                let de_sin =
                    crate::event::DeleteEvent::new_internal_invalid(filter!(f_or!([f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup_a")
                    )])));
                assert!(qs.delete(&de_sin).is_ok());
            },
            |_| {}
        );
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    //
    // This is the valid case, where the reference is MAY.
    #[test]
    fn test_delete_remove_referent_valid() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_a")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    //
    // this is the invalid case, where the reference is MUST.
    #[test]
    fn test_delete_remove_referent_invalid() {}

    // Delete of something that holds references.
    #[test]
    fn test_delete_remove_referee() {
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    // Delete something that has a self reference.
    #[test]
    fn test_delete_remove_reference_self() {
        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(
            r#"{
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "description": ["testgroup"],
                "uuid": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"],
                "member": ["d2b496bd-8493-47b7-8142-f568b5cf47ee"]
            }
        }"#,
        );

        let preload = vec![eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    #[test]
    fn test_delete_remove_reference_oauth2() {
        // Oauth2 types are also capable of uuid referencing to groups for their
        // scope maps, so we need to check that when the group is deleted, that the
        // scope map is also appropriately affected.
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            // (Attribute::Class, EntryClass::OAuth2ResourceServerBasic.into()),
            (
                Attribute::OAuth2RsName,
                Value::new_iname("test_resource_server")
            ),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                    btreeset![OAUTH2_SCOPE_READ.to_string()]
                )
                .expect("Invalid scope")
            )
        );

        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testgroup"))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::OAuth2RsName,
                        PartialValue::new_iname("test_resource_server")
                    )))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No entry");
                assert!(ue
                    .get_ava_as_oauthscopemaps(Attribute::OAuth2RsScopeMap)
                    .is_none())
            }
        );
    }

    #[qs_test]
    async fn test_delete_oauth2_rs_remove_sessions(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        let cred_id = cred.uuid;

        // Create a user
        let mut server_txn = server.write(curtime).await;

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
        let rs_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1")),
            (
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred.clone())
            )
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (
                Attribute::OAuth2RsName,
                Value::new_iname("test_resource_server")
            ),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_OPENID.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session and oauth2 session.

        let session_id = Uuid::new_v4();
        let pv_session_id = PartialValue::Refer(session_id);

        let parent_id = Uuid::new_v4();
        let pv_parent_id = PartialValue::Refer(parent_id);
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = SessionScope::ReadOnly;

        // Mod the user
        let modlist = modlist!([
            Modify::Present(
                Attribute::OAuth2Session.into(),
                Value::Oauth2Session(
                    session_id,
                    Oauth2Session {
                        parent: parent_id,
                        // Note we set the exp to None so we are not removing based on exp
                        state: SessionState::NeverExpires,
                        issued_at,
                        rs_uuid,
                    },
                )
            ),
            Modify::Present(
                Attribute::UserAuthTokenSession.into(),
                Value::Session(
                    parent_id,
                    Session {
                        label: "label".to_string(),
                        // Note we set the exp to None so we are not removing based on removal of the parent.
                        state: SessionState::NeverExpires,
                        // Need the other inner bits?
                        // for the gracewindow.
                        issued_at,
                        // Who actually created this?
                        issued_by,
                        cred_id,
                        // What is the access scope of this session? This is
                        // for auditing purposes.
                        scope,
                    },
                )
            ),
        ]);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");
        assert!(entry.attribute_equality(Attribute::UserAuthTokenSession, &pv_parent_id));
        assert!(entry.attribute_equality(Attribute::OAuth2Session, &pv_session_id));

        // Delete the oauth2 resource server.
        assert!(server_txn.internal_delete_uuid(rs_uuid).is_ok());

        // Oauth2 Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note the uat is present still.
        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        // The oauth2 session is revoked.
        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_ignore_references_for_regen(server: &QueryServer) {
        // Test that we ignore certain reference types that are specifically
        // regenerated in the code paths that *follow* refint. We have to have
        // refint before memberof just due to the nature of how it works. But
        // we still want to ignore invalid memberOf values and certain invalid
        // member sets from dyngroups to allow them to self-heal at run time.
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await;

        let tgroup_uuid = Uuid::new_v4();
        let dyn_uuid = Uuid::new_v4();
        let inv_mo_uuid = Uuid::new_v4();
        let inv_mb_uuid = Uuid::new_v4();

        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Uuid, Value::Uuid(dyn_uuid)),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (Attribute::DynMember, Value::Refer(inv_mb_uuid)),
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
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(tgroup_uuid)),
            (Attribute::MemberOf, Value::Refer(inv_mo_uuid))
        );

        let ce = CreateEvent::new_internal(vec![e_dyn, e_group]);
        assert!(server_txn.create(&ce).is_ok());

        let dyna = server_txn
            .internal_search_uuid(dyn_uuid)
            .expect("Failed to access dyn group");

        let dyn_member = dyna
            .get_ava_refer(Attribute::DynMember)
            .expect("Failed to get dyn member attribute");
        assert!(dyn_member.len() == 1);
        assert!(dyn_member.contains(&tgroup_uuid));

        let group = server_txn
            .internal_search_uuid(tgroup_uuid)
            .expect("Failed to access mo group");

        let grp_member = group
            .get_ava_refer(Attribute::MemberOf)
            .expect("Failed to get memberof attribute");
        assert!(grp_member.len() == 1);
        assert!(grp_member.contains(&dyn_uuid));

        assert!(server_txn.commit().is_ok());
    }
}
