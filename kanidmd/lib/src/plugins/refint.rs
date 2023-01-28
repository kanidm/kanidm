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

use hashbrown::HashSet as Set;
use kanidm_proto::v1::{ConsistencyError, PluginError};

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::filter::f_eq;
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::schema::SchemaTransaction;

// NOTE: This *must* be after base.rs!!!

pub struct ReferentialIntegrity;

impl ReferentialIntegrity {
    fn check_uuids_exist(
        qs: &mut QueryServerWriteTransaction,
        inner: Vec<PartialValue>,
    ) -> Result<(), OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            trace!("no reference types modified, skipping check");
            return Ok(());
        }

        let inner = inner.into_iter().map(|pv| f_eq("uuid", pv)).collect();

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
            Ok(())
        } else {
            admin_error!(
                "UUID reference set size differs from query result size <fast path, no uuid info available>"
            );
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string(),
            )))
        }
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

    #[instrument(level = "debug", name = "refint_post_delete", skip_all)]
    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Delete is pretty different to the other pre checks. This is
        // actually the bulk of the work we'll do to clean up references
        // when they are deleted.

        // Find all reference types in the schema
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();
        // Get the UUID of all entries we are deleting
        // let uuids: Vec<&Uuid> = cand.iter().map(|e| e.get_uuid()).collect();

        // Generate a filter which is the set of all schema reference types
        // as EQ to all uuid of all entries in delete. - this INCLUDES recycled
        // types too!
        let filt = filter_all!(FC::Or(
            // uuids
            // .iter()
            cand.iter()
                .map(|e| e.get_uuid())
                .flat_map(|u| ref_types.values().map(move |r_type| {
                    // For everything that references the uuid's in the deleted set.
                    f_eq(r_type.name.as_str(), PartialValue::Refer(u))
                }))
                .collect(),
        ));

        trace!("refint post_delete filter {:?}", filt);

        let removed_ids: BTreeSet<_> = cand
            .iter()
            .map(|e| PartialValue::Refer(e.get_uuid()))
            .collect();

        let work_set = qs.internal_search_writeable(&filt)?;

        let (pre_candidates, candidates) = work_set
            .into_iter()
            .map(|(pre, mut post)| {
                ref_types
                    .values()
                    .for_each(|attr| post.remove_avas(attr.name.as_str(), &removed_ids));
                (pre, post)
            })
            .unzip();

        qs.internal_apply_writable(pre_candidates, candidates)
    }

    #[instrument(level = "debug", name = "verify", skip(qs))]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Get all entries as cand
        //      build a cand-uuid set
        let filt_in = filter_all!(f_pres("class"));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let acu_map: Set<Uuid> = all_cand.iter().map(|e| e.get_uuid()).collect();

        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let mut res = Vec::new();
        // For all cands
        for c in &all_cand {
            // For all reference in each cand.
            for rtype in ref_types.values() {
                // If the attribute is present
                if let Some(vs) = c.get_ava_set(&rtype.name) {
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
    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        // Fast Path
        let mut vsiter = cand.iter().flat_map(|c| {
            ref_types
                .values()
                .filter_map(move |rtype| c.get_ava_set(&rtype.name))
        });

        // Could check len first?
        let mut i = Vec::with_capacity(cand.len() * 2);

        vsiter.try_for_each(|vs| {
            if let Some(uuid_iter) = vs.as_ref_uuid_iter() {
                uuid_iter.for_each(|u| {
                    i.push(PartialValue::Uuid(u))
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

        Self::check_uuids_exist(qs, i)
    }
}

#[cfg(test)]
mod tests {
    use kanidm_proto::v1::PluginError;

    use crate::event::CreateEvent;
    use crate::prelude::*;
    use crate::value::{Oauth2Session, Session};
    use time::OffsetDateTime;
    use uuid::uuid;

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
                        "name",
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
                    .internal_search(filter!(f_eq("name", PartialValue::new_iname("testgroup"))))
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
            ModifyList::new_list(vec![
                Modify::Present(
                    AttrString::from("member"),
                    Value::Refer(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                ),
                Modify::Present(
                    AttrString::from("member"),
                    Value::Refer(UUID_DOES_NOT_EXIST)
                ),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Purged(AttrString::from("member"))]),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_a"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
                Value::new_refer_s("d2b496bd-8493-47b7-8142-f568b5cf47ee").unwrap()
            )]),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                // Any pre_hooks we need. In this case, we need to trigger the delete of testgroup_a
                let de_sin = unsafe {
                    crate::event::DeleteEvent::new_internal_invalid(filter!(f_or!([f_eq(
                        "name",
                        PartialValue::new_iname("testgroup_a")
                    )])))
                };
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_a"))),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
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
            filter!(f_eq("name", PartialValue::new_iname("testgroup_b"))),
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
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(
                    uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                    btreeset!["read".to_string()]
                )
                .expect("Invalid scope")
            )
        );

        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testgroup")),
            (
                "uuid",
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            ("description", Value::new_utf8s("testgroup"))
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("name", PartialValue::new_iname("testgroup"))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        "oauth2_rs_name",
                        PartialValue::new_iname("test_resource_server")
                    )))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No entry");
                assert!(ue
                    .get_ava_as_oauthscopemaps("oauth2_rs_scope_map")
                    .is_none())
            }
        );
    }

    #[qs_test]
    async fn test_delete_oauth2_rs_remove_sessions(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::unix_epoch() + curtime;

        // Create a user
        let mut server_txn = server.write(curtime).await;

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
        let rs_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("person")),
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(tuuid)),
            ("description", Value::new_utf8s("testperson1")),
            ("displayname", Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("uuid", Value::Uuid(rs_uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["openid".to_string()])
                    .expect("invalid oauthscope")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session and oauth2 session.

        let session_id = Uuid::new_v4();
        let pv_session_id = PartialValue::Refer(session_id);

        let parent = Uuid::new_v4();
        let pv_parent_id = PartialValue::Refer(parent);
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = AccessScope::IdentityOnly;

        // Mod the user
        let modlist = modlist!([
            Modify::Present(
                "oauth2_session".into(),
                Value::Oauth2Session(
                    session_id,
                    Oauth2Session {
                        parent,
                        // Note we set the exp to None so we are not removing based on exp
                        expiry: None,
                        issued_at,
                        rs_uuid,
                    },
                )
            ),
            Modify::Present(
                "user_auth_token_session".into(),
                Value::Session(
                    parent,
                    Session {
                        label: "label".to_string(),
                        // Note we set the exp to None so we are not removing based on removal of the parent.
                        expiry: None,
                        // Need the other inner bits?
                        // for the gracewindow.
                        issued_at,
                        // Who actually created this?
                        issued_by,
                        // What is the access scope of this session? This is
                        // for auditing purposes.
                        scope,
                    },
                )
            ),
        ]);

        server_txn
            .internal_modify(&filter!(f_eq("uuid", PartialValue::Uuid(tuuid))), &modlist)
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");
        assert!(entry.attribute_equality("user_auth_token_session", &pv_parent_id));
        assert!(entry.attribute_equality("oauth2_session", &pv_session_id));

        // Delete the oauth2 resource server.
        assert!(server_txn.internal_delete_uuid(rs_uuid).is_ok());

        // Oauth2 Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note the uat is present still.
        assert!(entry.attribute_equality("user_auth_token_session", &pv_parent_id));
        // The oauth2 session is removed.
        assert!(!entry.attribute_equality("oauth2_session", &pv_session_id));

        assert!(server_txn.commit().is_ok());
    }
}
