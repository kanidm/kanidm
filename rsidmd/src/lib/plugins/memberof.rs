// Member Of
//
// Generate reverse relationships for groups to their members.
//
// Note referential integrity MUST be run first - this is to avoid the situation
// demonstrated in test_delete_mo_multi_cycle - that is, when we delete B, we trigger
// an update to C. C then triggers to A, which re-reades C + D. Because D still has not
// been update, it's stale reference to B flows to A, causing refint to fail the mod.
//
// As a result, we first need to run refint to clean up all dangling references, then memberof
// fixes the graph of memberships

use crate::audit::AuditScope;
use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntryValid};
use rsidm_proto::v1::{ConsistencyError, OperationError};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::{Modify, ModifyList};
use crate::plugins::Plugin;
use crate::server::QueryServerTransaction;
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};
use crate::value::{PartialValue, Value};

use std::collections::BTreeSet;
use uuid::Uuid;

lazy_static! {
    static ref CLASS_GROUP: PartialValue = PartialValue::new_iutf8s("group");
}

pub struct MemberOf;

fn affected_uuids<'a, STATE>(
    au: &mut AuditScope,
    changed: Vec<&'a Entry<EntryValid, STATE>>,
) -> Vec<&'a Uuid>
where
    STATE: std::fmt::Debug,
{
    // From the list of groups which were changed in this operation:
    let changed_groups: Vec<_> = changed
        .into_iter()
        .filter(|e| e.attribute_value_pres("class", &CLASS_GROUP))
        .inspect(|e| {
            audit_log!(au, "group reporting change: {:?}", e);
        })
        .collect();

    // Now, build a map of all UUID's that will require updates as a result of this change
    let mut affected_uuids: Vec<&Uuid> = changed_groups
        .iter()
        .filter_map(|e| {
            // Only groups with member get collected up here.
            e.get_ava("member")
        })
        // Flatten the member's to the list.
        .flatten()
        .filter_map(|uv| uv.to_ref_uuid())
        .collect();

    // IDEA: promote groups to head of the affected_uuids set!
    //
    // This isn't worth doing - it's only used in create/delete, it would not
    // really make a large performance difference. Better to target improvements
    // in the apply_memberof fn.
    affected_uuids.sort();
    // Remove dups
    affected_uuids.dedup();

    affected_uuids
}

fn apply_memberof(
    au: &mut AuditScope,
    qs: &mut QueryServerWriteTransaction,
    affected_uuids: Vec<&Uuid>,
) -> Result<(), OperationError> {
    audit_log!(au, " => entering apply_memberof");
    audit_log!(au, "affected uuids -> {:?}", affected_uuids);

    // Apply member takes a list of changes. We then filter that to only the changed groups
    // and using this, we determine a list of UUID's from members that will be required to
    // re-examine their MO attributes.

    // Given the list of UUID that require changes, we attempt to trigger MO updates on groups
    // first to stabilise the MO graph before we start triggering changes on entries.
    //
    // it's important to note that each change itself, especially groups, could trigger there
    // own recursive updates until the base case - stable, no changes - is reached.
    //
    // That means the termination of recursion is ALWAYS to be found in the post_modify
    // callback, as regardless of initial entry point, all subsequent MO internal operations
    // are modifies - it is up to post_modify to break cycles!

    // Now work on the affected set.

    // For each affected uuid
    for a_uuid in affected_uuids {
        // search where group + Eq("member": "uuid")
        let groups = try_audit!(
            au,
            qs.internal_search(
                au,
                filter!(f_and!([
                    f_eq("class", CLASS_GROUP.clone()),
                    f_eq("member", PartialValue::new_refer_r(a_uuid))
                ]))
            )
        );
        // get UUID of all groups + all memberof values
        let mut dir_mo_set: Vec<Value> = groups
            .iter()
            .map(|g| {
                // These are turned into reference values.
                Value::new_refer(g.get_uuid().clone())
            })
            .collect();

        // No need to dedup this. Sorting could be of questionable
        // value too though ...
        dir_mo_set.sort();
        dir_mo_set.dedup();

        let mut mo_set: Vec<Value> = groups
            .iter()
            .map(|g| {
                // TODO #61: This could be more effecient
                let mut v = vec![Value::new_refer(g.get_uuid().clone())];
                match g.get_ava("memberof") {
                    Some(mos) => {
                        for mo in mos {
                            // This is cloning the existing reference values
                            v.push(mo.clone())
                        }
                    }
                    None => {}
                }
                v
            })
            .flatten()
            .collect();

        mo_set.sort();
        mo_set.dedup();

        audit_log!(au, "Updating {:?} to be dir mo {:?}", a_uuid, dir_mo_set);
        audit_log!(au, "Updating {:?} to be mo {:?}", a_uuid, mo_set);

        // first add a purged memberof to remove all mo we no longer
        // support.
        // TODO #61: Could this be more efficient
        // TODO #68: Could this affect replication? Or should the CL work out the
        // true diff of the operation?
        let mo_purge = vec![
            Modify::Present("class".to_string(), Value::new_class("memberof")),
            Modify::Purged("memberof".to_string()),
            Modify::Purged("directmemberof".to_string()),
        ];

        // create modify present memberof all uuids
        let mod_set: Vec<_> = mo_purge
            .into_iter()
            .chain(
                mo_set
                    .into_iter()
                    .map(|mo_uuid| Modify::Present("memberof".to_string(), mo_uuid)),
            )
            .chain(
                dir_mo_set
                    .into_iter()
                    .map(|mo_uuid| Modify::Present("directmemberof".to_string(), mo_uuid)),
            )
            .collect();

        // apply to affected uuid
        let modlist = ModifyList::new_list(mod_set);

        try_audit!(
            au,
            qs.internal_modify(
                au,
                filter!(f_eq("uuid", PartialValue::new_uuid(a_uuid.clone()))),
                modlist,
            )
        );
    }

    Ok(())
}

impl Plugin for MemberOf {
    fn id() -> &'static str {
        "memberof"
    }

    // TODO #61: We could make this more effecient by limiting change detection to ONLY member/memberof
    // attrs rather than any attrs.

    fn post_create(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        //
        // Trigger apply_memberof on all because they changed.
        let cand_refs: Vec<&Entry<_, _>> = cand.iter().map(|e| e).collect();
        let uuids = affected_uuids(au, cand_refs);
        apply_memberof(au, qs, uuids)
    }

    fn post_modify(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // The condition here is critical - ONLY trigger on entries where changes occur!
        let mut changed: Vec<&Uuid> = pre_cand
            .iter()
            .zip(cand.iter())
            .filter(|(pre, post)| {
                // This is the base case to break cycles in recursion!
                (
                        // If it was a group, or will become a group.
                        post.attribute_value_pres("class", &CLASS_GROUP)
                            || pre.attribute_value_pres("class", &CLASS_GROUP)
                    )
                    // And the group has changed ...
                    && pre != post
                // Then memberof should be updated!
            })
            // Flatten the pre-post tuples. We no longer care if it was
            // pre-post
            .flat_map(|(pre, post)| vec![pre, post])
            .inspect(|e| {
                audit_log!(au, "group reporting change: {:?}", e);
            })
            .filter_map(|e| {
                // Only groups with member get collected up here.
                e.get_ava_reference_uuid("member")
            })
            // Flatten the uuid reference lists.
            .flatten()
            .collect();

        // Now tidy them up to reduce excesse searches/work.
        changed.sort();
        changed.dedup();

        apply_memberof(au, qs, changed)
    }

    fn pre_delete(
        _au: &mut AuditScope,
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // It is not valid for a recycled group to be considered
        // a member of any other type. We simply purge the ava from
        // the entries. This is because it will be removed from all
        // locations where it *was* a member.
        //
        // As a result, on restore, the graph of where it was a member
        // would have to be rebuilt.
        //
        // AN interesting possibility could be NOT to purge MO on delete
        // and use that to rebuild the forward graph of member -> item, but
        // due to the nature of MO, we do not know the difference between
        // direct and indirect membership, meaning we would be safer
        // to not do this.

        // NOTE: DO NOT purge directmemberof - we use that to restore memberships
        // in recycle revive!

        cand.iter_mut().for_each(|e| e.purge_ava("memberof"));
        Ok(())
    }

    fn post_delete(
        au: &mut AuditScope,
        qs: &mut QueryServerWriteTransaction,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        //
        // Trigger apply_memberof on all - because they all changed.
        let cand_refs: Vec<&Entry<_, _>> = cand.iter().map(|e| e).collect();
        let uuids = affected_uuids(au, cand_refs);
        apply_memberof(au, qs, uuids)
    }

    fn verify(
        au: &mut AuditScope,
        qs: &QueryServerReadTransaction,
    ) -> Vec<Result<(), ConsistencyError>> {
        let mut r = Vec::new();

        let filt_in = filter!(f_pres("class"));

        let all_cand = match qs
            .internal_search(au, filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        // for each entry in the DB (live).
        for e in all_cand {
            // create new map
            // let mo_set: BTreeMap<String, ()> = BTreeMap::new();
            // searcch direct memberships of live groups.
            let filt_in = filter!(f_eq(
                "member",
                PartialValue::new_refer(e.get_uuid().clone())
            ));

            let direct_memberof = match qs
                .internal_search(au, filt_in)
                .map_err(|_| ConsistencyError::QueryServerSearchFailure)
            {
                Ok(d_mo) => d_mo,
                Err(e) => return vec![Err(e)],
            };
            // for all direct -> add uuid to map

            let d_groups_set: BTreeSet<&Uuid> =
                direct_memberof.iter().map(|e| e.get_uuid()).collect();

            audit_log!(au, "Direct groups {:?} -> {:?}", e.get_uuid(), d_groups_set);

            let dmos: Vec<&Uuid> = match e.get_ava_reference_uuid("directmemberof") {
                // Avoid a reference issue to return empty set
                Some(dmos) => dmos,
                // No memberof, return empty set.
                None => Vec::new(),
            };

            audit_log!(au, "DMO groups {:?} -> {:?}", e.get_uuid(), dmos);

            if dmos.len() != direct_memberof.len() {
                audit_log!(
                    au,
                    "direct set and mo set differ in size: {:?}",
                    e.get_uuid()
                );
                r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                // Next entry
                continue;
            };

            for mo_uuid in dmos {
                if !d_groups_set.contains(mo_uuid) {
                    audit_log!(
                        au,
                        "Entry {:?}, MO {:?} not in direct groups",
                        e.get_uuid(),
                        mo_uuid
                    );
                    r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                    // Next entry
                    continue;
                }
            }

            // Could check all dmos in mos?

            /* To check nested! */
            // add all direct to a stack
            // for all in stack
            // check their direct memberships
            // if not in map
            // add to map
            // push to stack

            // check mo == map set
            // if not, consistency error!
        }

        r
    }
}

#[cfg(test)]
mod tests {
    // #[macro_use]
    // use crate::plugins::Plugin;
    use crate::entry::{Entry, EntryInvalid, EntryNew};
    // use crate::error::OperationError;
    use crate::modify::{Modify, ModifyList};
    use crate::server::{QueryServerTransaction, QueryServerWriteTransaction};
    use crate::value::{PartialValue, Value};

    static UUID_A: &'static str = "aaaaaaaa-f82e-4484-a407-181aa03bda5c";
    static UUID_B: &'static str = "bbbbbbbb-2438-4384-9891-48f4c8172e9b";
    static UUID_C: &'static str = "cccccccc-9b01-423f-9ba6-51aa4bbd5dd2";
    static UUID_D: &'static str = "dddddddd-2ab3-48e3-938d-1b4754cd2984";

    static EA: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_a"],
                "uuid": ["aaaaaaaa-f82e-4484-a407-181aa03bda5c"]
            }
        }"#;

    static EB: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_b"],
                "uuid": ["bbbbbbbb-2438-4384-9891-48f4c8172e9b"]
            }
        }"#;

    static EC: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_c"],
                "uuid": ["cccccccc-9b01-423f-9ba6-51aa4bbd5dd2"]
            }
        }"#;

    static ED: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_d"],
                "uuid": ["dddddddd-2ab3-48e3-938d-1b4754cd2984"]
            }
        }"#;

    macro_rules! assert_memberof_int {
        (
            $au:expr,
            $qs:expr,
            $ea:expr,
            $eb:expr,
            $mo:expr,
            $cand:expr
        ) => {{
            let filt = filter!(f_and!([
                f_eq("uuid", PartialValue::new_uuids($ea).unwrap()),
                f_eq($mo, PartialValue::new_refer_s($eb).unwrap())
            ]));
            let cands = $qs
                .internal_search($au, filt)
                .expect("Internal search failure");
            println!("{:?}", cands);
            assert!(cands.len() == $cand);
        }};
    }

    macro_rules! assert_memberof {
        (
            $au:expr,
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($au, $qs, $ea, $eb, "memberof", 1);
        }};
    }

    macro_rules! assert_dirmemberof {
        (
            $au:expr,
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($au, $qs, $ea, $eb, "directmemberof", 1);
        }};
    }

    macro_rules! assert_not_memberof {
        (
            $au:expr,
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($au, $qs, $ea, $eb, "memberof", 0);
        }};
    }

    macro_rules! assert_not_dirmemberof {
        (
            $au:expr,
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($au, $qs, $ea, $eb, "directmemberof", 0);
        }};
    }

    #[test]
    fn test_create_mo_single() {
        // A -> B
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_create_mo_nested() {
        // A -> B -> C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb, ec];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                // This is due to nestig, C should be MO both!
                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_create_mo_cycle() {
        // A -> B -> C -
        // ^-----------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb, ec];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(au, qs, UUID_A, UUID_A);
                assert_memberof!(au, qs, UUID_A, UUID_B);
                assert_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_memberof!(au, qs, UUID_B, UUID_B);
                assert_memberof!(au, qs, UUID_B, UUID_C);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_create_mo_multi_cycle() {
        // A -> B -> C --> D -
        // ^-----------/    /
        // |---------------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let mut ed: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());

        ec.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("member", &Value::new_refer_s(&UUID_D).unwrap());

        ed.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb, ec, ed];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(au, qs, UUID_A, UUID_A);
                assert_memberof!(au, qs, UUID_A, UUID_B);
                assert_memberof!(au, qs, UUID_A, UUID_C);
                assert_memberof!(au, qs, UUID_A, UUID_D);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_memberof!(au, qs, UUID_B, UUID_B);
                assert_memberof!(au, qs, UUID_B, UUID_C);
                assert_memberof!(au, qs, UUID_B, UUID_D);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_memberof!(au, qs, UUID_C, UUID_C);
                assert_memberof!(au, qs, UUID_C, UUID_D);

                assert_memberof!(au, qs, UUID_D, UUID_A);
                assert_memberof!(au, qs, UUID_D, UUID_B);
                assert_memberof!(au, qs, UUID_D, UUID_C);
                assert_memberof!(au, qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_dirmemberof!(au, qs, UUID_A, UUID_C);
                assert_dirmemberof!(au, qs, UUID_A, UUID_D);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_B);
                assert_dirmemberof!(au, qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_simple() {
        // A    B
        // Add member
        // A -> B
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s(&UUID_B).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_nested_1() {
        // A    B -> C
        // Add member A -> B
        // A -> B -> C
        let ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s(&UUID_B).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_nested_2() {
        // A -> B    C
        // Add member B -> C
        // A -> B -> C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_B).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s(&UUID_C).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_cycle() {
        // A -> B -> C
        //
        // Add member C -> A
        // A -> B -> C -
        // ^-----------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s(&UUID_A).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(au, qs, UUID_A, UUID_A);
                assert_memberof!(au, qs, UUID_A, UUID_B);
                assert_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_memberof!(au, qs, UUID_B, UUID_B);
                assert_memberof!(au, qs, UUID_B, UUID_C);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_add_multi_cycle() {
        // A -> B -> C --> D
        //
        // Add member C -> A
        // Add member C -> D
        // Add member D -> A
        //
        // A -> B -> C --> D -
        // ^-----------/    /
        // |---------------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let ed: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("member", &Value::new_refer_s(&UUID_D).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_or!([
                f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap()),
                f_eq("uuid", PartialValue::new_uuids(&UUID_D).unwrap()),
            ])),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                Value::new_refer_s(&UUID_A).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(au, qs, UUID_A, UUID_A);
                assert_memberof!(au, qs, UUID_A, UUID_B);
                assert_memberof!(au, qs, UUID_A, UUID_C);
                assert_memberof!(au, qs, UUID_A, UUID_D);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_memberof!(au, qs, UUID_B, UUID_B);
                assert_memberof!(au, qs, UUID_B, UUID_C);
                assert_memberof!(au, qs, UUID_B, UUID_D);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_memberof!(au, qs, UUID_C, UUID_C);
                assert_memberof!(au, qs, UUID_C, UUID_D);

                assert_memberof!(au, qs, UUID_D, UUID_A);
                assert_memberof!(au, qs, UUID_D, UUID_B);
                assert_memberof!(au, qs, UUID_D, UUID_C);
                assert_memberof!(au, qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_dirmemberof!(au, qs, UUID_A, UUID_C);
                assert_dirmemberof!(au, qs, UUID_A, UUID_D);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_B);
                assert_dirmemberof!(au, qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_simple() {
        // A -> B
        // remove member A -> B
        // A    B
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                PartialValue::new_refer_s(&UUID_B).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);

                assert_not_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_nested_1() {
        // A -> B -> C
        // Remove A -> B
        // A    B -> C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                PartialValue::new_refer_s(&UUID_B).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_not_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_not_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_nested_2() {
        // A -> B -> C
        // Remove B -> C
        // A -> B    C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_B).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                PartialValue::new_refer_s(&UUID_C).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_not_memberof!(au, qs, UUID_C, UUID_A);
                assert_not_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_cycle() {
        // A -> B -> C -
        // ^-----------/
        // Remove C -> A
        // A -> B -> C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        ec.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                PartialValue::new_refer_s(&UUID_A).unwrap()
            )]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_modify_mo_del_multi_cycle() {
        // A -> B -> C --> D -
        // ^-----------/    /
        // |---------------/
        //
        // Remove C -> D
        // Remove C -> A
        //
        // A -> B -> C    D -
        // ^                /
        // |---------------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let mut ed: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        ec.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("member", &Value::new_refer_s(&UUID_D).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        ed.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap())),
            ModifyList::new_list(vec![
                Modify::Removed(
                    "member".to_string(),
                    PartialValue::new_refer_s(&UUID_A).unwrap()
                ),
                Modify::Removed(
                    "member".to_string(),
                    PartialValue::new_refer_s(&UUID_D).unwrap()
                ),
            ]),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);
                assert_memberof!(au, qs, UUID_A, UUID_D);

                assert_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);
                assert_memberof!(au, qs, UUID_B, UUID_D);

                assert_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);
                assert_memberof!(au, qs, UUID_C, UUID_D);

                assert_not_memberof!(au, qs, UUID_D, UUID_A);
                assert_not_memberof!(au, qs, UUID_D, UUID_B);
                assert_not_memberof!(au, qs, UUID_D, UUID_C);
                assert_not_memberof!(au, qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);
                assert_dirmemberof!(au, qs, UUID_A, UUID_D);

                assert_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_delete_mo_simple() {
        // X -> B
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);

                assert_not_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_delete_mo_nested_head() {
        // X -> B -> C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_not_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_nested_branch() {
        // A -> X -> C
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_B).unwrap())),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_C);

                assert_not_memberof!(au, qs, UUID_C, UUID_A);
                assert_not_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_cycle() {
        // X -> B -> C -
        // ^-----------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());

        ec.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_B, UUID_A);
                assert_not_memberof!(au, qs, UUID_B, UUID_B);
                assert_not_memberof!(au, qs, UUID_B, UUID_C);

                assert_not_memberof!(au, qs, UUID_C, UUID_A);
                assert_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_multi_cycle() {
        // A -> X -> C --> D -
        // ^-----------/    /
        // |---------------/
        let mut ea: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let mut ed: Entry<EntryInvalid, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ea.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());

        eb.add_ava("member", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());

        ec.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("member", &Value::new_refer_s(&UUID_D).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());

        ed.add_ava("member", &Value::new_refer_s(&UUID_A).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_A).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_B).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_C).unwrap());
        ed.add_ava("memberof", &Value::new_refer_s(&UUID_D).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_B).unwrap())),
            None,
            |au: &mut AuditScope, qs: &QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(au, qs, UUID_A, UUID_B);
                assert_not_memberof!(au, qs, UUID_A, UUID_A);
                assert_memberof!(au, qs, UUID_A, UUID_C);
                assert_memberof!(au, qs, UUID_A, UUID_D);

                assert_not_memberof!(au, qs, UUID_C, UUID_A);
                assert_not_memberof!(au, qs, UUID_C, UUID_B);
                assert_not_memberof!(au, qs, UUID_C, UUID_C);
                assert_not_memberof!(au, qs, UUID_C, UUID_D);

                assert_not_memberof!(au, qs, UUID_D, UUID_A);
                assert_not_memberof!(au, qs, UUID_D, UUID_B);
                assert_memberof!(au, qs, UUID_D, UUID_C);
                assert_not_memberof!(au, qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_A, UUID_B);
                assert_dirmemberof!(au, qs, UUID_A, UUID_C);
                assert_dirmemberof!(au, qs, UUID_A, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(au, qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(au, qs, UUID_C, UUID_B);
                assert_dirmemberof!(au, qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(au, qs, UUID_D, UUID_D);
            }
        );
    }
}
