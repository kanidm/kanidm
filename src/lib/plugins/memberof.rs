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
use crate::error::{ConsistencyError, OperationError};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::{Modify, ModifyList};
use crate::plugins::Plugin;
use crate::server::QueryServerTransaction;
use crate::server::{QueryServerReadTransaction, QueryServerWriteTransaction};

use std::collections::BTreeMap;

pub struct MemberOf;

fn affected_uuids<'a, STATE>(
    au: &mut AuditScope,
    changed: Vec<&'a Entry<EntryValid, STATE>>,
) -> Vec<&'a String>
where
    STATE: std::fmt::Debug,
{
    // From the list of groups which were changed in this operation:
    let changed_groups: Vec<_> = changed
        .into_iter()
        .filter(|e| e.attribute_value_pres("class", "group"))
        .inspect(|e| {
            audit_log!(au, "group reporting change: {:?}", e);
        })
        .collect();

    // Now, build a map of all UUID's that will require updates as a result of this change
    let mut affected_uuids: Vec<&String> = changed_groups
        .iter()
        .filter_map(|e| {
            // Only groups with member get collected up here.
            e.get_ava("member")
        })
        // Flatten the member's to the list.
        .flatten()
        .collect();

    // Sort
    // TODO: promote groups to head of the affected_uuids set!
    // this could be assisted by indexing in the future by providing a custom compare
    // algo!!!
    affected_uuids.sort();
    // Remove dups
    affected_uuids.dedup();

    affected_uuids
}

fn apply_memberof(
    au: &mut AuditScope,
    qs: &QueryServerWriteTransaction,
    affected_uuids: Vec<&String>,
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
                filter!(f_and!([f_eq("class", "group"), f_eq("member", a_uuid)]))
            )
        );
        // get UUID of all groups + all memberof values
        let mut dir_mo_set: Vec<_> = groups.iter().map(|g| g.get_uuid().clone()).collect();

        // No need to dedup this. Sorting could be of questionable
        // value too though ...
        dir_mo_set.sort();

        let mut mo_set: Vec<_> = groups
            .iter()
            .map(|g| {
                // TODO: This could be more effecient
                let mut v = vec![g.get_uuid().clone()];
                match g.get_ava("memberof") {
                    Some(mos) => {
                        for mo in mos {
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
        // TODO: Could this be more efficient
        let mo_purge = vec![
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
            qs.internal_modify(au, filter!(f_eq("uuid", a_uuid)), modlist,)
        );
    }

    Ok(())
}

impl Plugin for MemberOf {
    fn id() -> &'static str {
        "memberof"
    }

    // TODO: We could make this more effecient by limiting change detection to ONLY member/memberof
    // attrs rather than any attrs.

    fn post_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
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
        qs: &QueryServerWriteTransaction,
        pre_cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        cand: &Vec<Entry<EntryValid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // The condition here is critical - ONLY trigger on entries where changes occur!
        let mut changed: Vec<&String> = pre_cand
            .iter()
            .zip(cand.iter())
            .filter(|(pre, post)| {
                // This is the base case to break cycles in recursion!
                pre != post
                    && (
                        // AND if it was a group, or will become a group.
                        post.attribute_value_pres("class", "group")
                            || pre.attribute_value_pres("class", "group")
                    )
            })
            // Flatten the pre-post tuples. We no longer care if it was
            // pre-post
            // TODO: Could this be more effecient?
            .flat_map(|(pre, post)| vec![pre, post])
            .inspect(|e| {
                audit_log!(au, "group reporting change: {:?}", e);
            })
            .filter_map(|e| {
                // Only groups with member get collected up here.
                e.get_ava("member")
            })
            // Flatten the uuid lists.
            .flatten()
            .collect();

        // Now tidy them up.
        changed.sort();
        changed.dedup();

        apply_memberof(au, qs, changed)
    }

    fn pre_delete(
        _au: &mut AuditScope,
        _qs: &QueryServerWriteTransaction,
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
        qs: &QueryServerWriteTransaction,
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
            let filt_in = filter!(f_eq("member", e.get_uuid().as_str()));

            let direct_memberof = match qs
                .internal_search(au, filt_in)
                .map_err(|_| ConsistencyError::QueryServerSearchFailure)
            {
                Ok(d_mo) => d_mo,
                Err(e) => return vec![Err(e)],
            };
            // for all direct -> add uuid to map

            let d_groups_set: BTreeMap<&String, ()> =
                direct_memberof.iter().map(|e| (e.get_uuid(), ())).collect();

            audit_log!(au, "Direct groups {:?} -> {:?}", e.get_uuid(), d_groups_set);

            let dmos = match e.get_ava(&"directmemberof".to_string()) {
                // Avoid a reference issue to return empty set
                Some(dmos) => dmos.clone(),
                None => {
                    // No memberof, return empty set.
                    Vec::new()
                }
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
                if !d_groups_set.contains_key(&mo_uuid) {
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

    static EA: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_a"],
                "uuid": ["aaaaaaaa-f82e-4484-a407-181aa03bda5c"]
            }
        }"#;

    static UUID_A: &'static str = "aaaaaaaa-f82e-4484-a407-181aa03bda5c";

    static EB: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_b"],
                "uuid": ["bbbbbbbb-2438-4384-9891-48f4c8172e9b"]
            }
        }"#;

    static UUID_B: &'static str = "bbbbbbbb-2438-4384-9891-48f4c8172e9b";

    static EC: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_c"],
                "uuid": ["cccccccc-9b01-423f-9ba6-51aa4bbd5dd2"]
            }
        }"#;

    static UUID_C: &'static str = "cccccccc-9b01-423f-9ba6-51aa4bbd5dd2";

    static ED: &'static str = r#"{
            "valid": null,
            "state": null,
            "attrs": {
                "class": ["group"],
                "name": ["testgroup_d"],
                "uuid": ["dddddddd-2ab3-48e3-938d-1b4754cd2984"]
            }
        }"#;

    static UUID_D: &'static str = "dddddddd-2ab3-48e3-938d-1b4754cd2984";

    macro_rules! assert_memberof_int {
        (
            $au:expr,
            $qs:expr,
            $ea:expr,
            $eb:expr,
            $mo:expr,
            $cand:expr
        ) => {{
            let filt = filter!(f_and!([f_eq("uuid", $ea), f_eq($mo, $eb)]));
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        ea.add_ava("member", UUID_B);

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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("member", UUID_C);

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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("member", UUID_C);
        ec.add_ava("member", UUID_A);

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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        let mut ed: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(ED).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("member", UUID_C);

        ec.add_ava("member", UUID_A);
        ec.add_ava("member", UUID_D);

        ed.add_ava("member", UUID_A);

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
        let ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                UUID_B.to_string()
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
        let ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        eb.add_ava("member", UUID_C);

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                UUID_B.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_B)),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                UUID_C.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("member", UUID_C);

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_C)),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                UUID_A.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        let ed: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(ED).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("member", UUID_C);
        ec.add_ava("member", UUID_D);

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_or!([f_eq("uuid", UUID_C), f_eq("uuid", UUID_D),])),
            ModifyList::new_list(vec![Modify::Present(
                "member".to_string(),
                UUID_A.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("memberof", UUID_A);

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                UUID_B.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("memberof", UUID_A);
        eb.add_ava("member", UUID_C);
        ec.add_ava("memberof", UUID_B);

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                UUID_B.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("memberof", UUID_A);
        eb.add_ava("member", UUID_C);
        ec.add_ava("memberof", UUID_B);
        ec.add_ava("memberof", UUID_A);

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_B)),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                UUID_C.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        ea.add_ava("memberof", UUID_C);
        ea.add_ava("memberof", UUID_B);
        ea.add_ava("memberof", UUID_A);

        eb.add_ava("member", UUID_C);
        eb.add_ava("memberof", UUID_C);
        eb.add_ava("memberof", UUID_B);
        eb.add_ava("memberof", UUID_A);

        ec.add_ava("member", UUID_A);
        ec.add_ava("memberof", UUID_C);
        ec.add_ava("memberof", UUID_B);
        ec.add_ava("memberof", UUID_A);

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_C)),
            ModifyList::new_list(vec![Modify::Removed(
                "member".to_string(),
                UUID_A.to_string()
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        let mut ed: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(ED).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        ea.add_ava("memberof", UUID_D);
        ea.add_ava("memberof", UUID_C);
        ea.add_ava("memberof", UUID_B);
        ea.add_ava("memberof", UUID_A);

        eb.add_ava("member", UUID_C);
        eb.add_ava("memberof", UUID_D);
        eb.add_ava("memberof", UUID_C);
        eb.add_ava("memberof", UUID_B);
        eb.add_ava("memberof", UUID_A);

        ec.add_ava("member", UUID_A);
        ec.add_ava("member", UUID_D);
        ec.add_ava("memberof", UUID_D);
        ec.add_ava("memberof", UUID_C);
        ec.add_ava("memberof", UUID_B);
        ec.add_ava("memberof", UUID_A);

        ed.add_ava("member", UUID_A);
        ed.add_ava("memberof", UUID_D);
        ed.add_ava("memberof", UUID_C);
        ed.add_ava("memberof", UUID_B);
        ed.add_ava("memberof", UUID_A);

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_C)),
            ModifyList::new_list(vec![
                Modify::Removed("member".to_string(), UUID_A.to_string()),
                Modify::Removed("member".to_string(), UUID_D.to_string()),
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("memberof", UUID_A);

        let preload = vec![ea, eb];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("memberof", UUID_A);

        eb.add_ava("member", UUID_C);
        ec.add_ava("memberof", UUID_A);
        ec.add_ava("memberof", UUID_B);

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        eb.add_ava("memberof", UUID_A);

        eb.add_ava("member", UUID_C);
        ec.add_ava("memberof", UUID_A);
        ec.add_ava("memberof", UUID_B);

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_B)),
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        ea.add_ava("memberof", UUID_A);
        ea.add_ava("memberof", UUID_B);
        ea.add_ava("memberof", UUID_C);

        eb.add_ava("member", UUID_C);
        eb.add_ava("memberof", UUID_A);
        eb.add_ava("memberof", UUID_B);
        eb.add_ava("memberof", UUID_C);

        ec.add_ava("member", UUID_A);
        ec.add_ava("memberof", UUID_A);
        ec.add_ava("memberof", UUID_B);
        ec.add_ava("memberof", UUID_C);

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_A)),
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
        let mut ea: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EA).expect("Json parse failure");

        let mut eb: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EB).expect("Json parse failure");

        let mut ec: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(EC).expect("Json parse failure");

        let mut ed: Entry<EntryInvalid, EntryNew> =
            serde_json::from_str(ED).expect("Json parse failure");

        ea.add_ava("member", UUID_B);
        ea.add_ava("memberof", UUID_A);
        ea.add_ava("memberof", UUID_B);
        ea.add_ava("memberof", UUID_C);
        ea.add_ava("memberof", UUID_D);

        eb.add_ava("member", UUID_C);
        eb.add_ava("memberof", UUID_A);
        eb.add_ava("memberof", UUID_B);
        eb.add_ava("memberof", UUID_C);
        eb.add_ava("memberof", UUID_D);

        ec.add_ava("member", UUID_A);
        ec.add_ava("member", UUID_D);
        ec.add_ava("memberof", UUID_A);
        ec.add_ava("memberof", UUID_B);
        ec.add_ava("memberof", UUID_C);
        ec.add_ava("memberof", UUID_D);

        ed.add_ava("member", UUID_A);
        ed.add_ava("memberof", UUID_A);
        ed.add_ava("memberof", UUID_B);
        ed.add_ava("memberof", UUID_C);
        ed.add_ava("memberof", UUID_D);

        let preload = vec![ea, eb, ec, ed];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", UUID_B)),
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
