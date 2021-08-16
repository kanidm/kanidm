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

use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntrySealed};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::value::{PartialValue, Value};
use crate::valueset::ValueSet;
use kanidm_proto::v1::{ConsistencyError, OperationError};

use hashbrown::HashMap;
use uuid::Uuid;

lazy_static! {
    static ref CLASS_GROUP: PartialValue = PartialValue::new_class("group");
    static ref CLASS_MEMBEROF: Value = Value::new_class("memberof");
}

pub struct MemberOf;

type EntrySealedCommitted = Entry<EntrySealed, EntryCommitted>;
type EntryInvalidCommitted = Entry<EntryInvalid, EntryCommitted>;
type EntryTuple = (EntrySealedCommitted, EntryInvalidCommitted);

fn do_memberof(
    au: &mut AuditScope,
    qs: &QueryServerWriteTransaction,
    uuid: &Uuid,
    tgte: &mut EntryInvalidCommitted,
) -> Result<(), OperationError> {
    //  search where we are member
    let groups = qs
        .internal_search(
            au,
            filter!(f_and!([
                f_eq("class", CLASS_GROUP.clone()),
                f_eq("member", PartialValue::new_refer(*uuid))
            ])),
        )
        .map_err(|e| {
            ladmin_error!(au, "internal search failure -> {:?}", e);
            e
        })?;

    // Ensure we are MO capable.
    tgte.add_ava("class", CLASS_MEMBEROF.clone());
    // Clear the dmo + mos, we will recreate them now.
    // This is how we handle deletes/etc.
    tgte.pop_ava("memberof");
    tgte.pop_ava("directmemberof");
    // Add all the direct mo's and mos.
    groups.iter().for_each(|g| {
        // TODO: Change add_ava to remove this alloc/clone.
        let dmo = Value::new_refer(*g.get_uuid());
        tgte.add_ava("directmemberof", dmo.clone());
        tgte.add_ava("memberof", dmo);

        if let Some(miter) = g.get_ava("memberof") {
            miter.for_each(|mo| {
                tgte.add_ava("memberof", mo.clone());
            })
        };
    });

    ltrace!(
        au,
        "Updating {:?} to be dir mo {:?}",
        uuid,
        tgte.get_ava_set("directmemberof")
    );
    ltrace!(
        au,
        "Updating {:?} to be mo {:?}",
        uuid,
        tgte.get_ava_set("memberof")
    );

    Ok(())
}

#[allow(clippy::cognitive_complexity)]
fn apply_memberof(
    au: &mut AuditScope,
    qs: &QueryServerWriteTransaction,
    // TODO: Experiment with HashSet/BTreeSet here instead of vec.
    // May require https://github.com/rust-lang/rust/issues/62924 to allow poping
    mut group_affect: Vec<Uuid>,
) -> Result<(), OperationError> {
    ltrace!(au, " => entering apply_memberof");
    ltrace!(au, " => initial group_affect {:?}", group_affect);

    // We can't cache groups, because we need to be continually writing
    // and querying them. But we can cache anything we find in the process
    // to speed up the later other_affect write op, and we can use this
    // to avoid loading things that aren't groups.
    // All other changed entries (mo, dmo cleared)
    let mut other_cache: HashMap<Uuid, EntryTuple> = HashMap::with_capacity(group_affect.len() * 2);
    while !group_affect.is_empty() {
        group_affect.sort();
        group_affect.dedup();
        // Prep the write lists
        let mut pre_candidates = Vec::with_capacity(group_affect.len());
        let mut candidates = Vec::with_capacity(group_affect.len());

        // Ignore recycled/tombstones
        let filt = filter!(FC::Or(
            group_affect
                .drain(0..)
                .map(|u| f_eq("uuid", PartialValue::new_uuid(u)))
                .collect()
        ));

        let mut work_set = qs.internal_search_writeable(au, &filt)?;
        // Load the vecdeque with this batch.

        while let Some((pre, mut tgte)) = work_set.pop() {
            let guuid = *pre.get_uuid();
            // load the entry from the db.
            if !tgte.attribute_equality("class", &CLASS_GROUP) {
                // It's not a group, we'll deal with you later. We should NOT
                // have seen this UUID before, as either we are on the first
                // iteration OR the checks belowe should have filtered it out.
                ltrace!(au, "not a group, delaying update to -> {:?}", guuid);
                other_cache.insert(guuid, (pre, tgte));
                continue;
            }

            ltrace!(au, "=> processing group update -> {:?}", guuid);

            do_memberof(au, qs, &guuid, &mut tgte)?;

            // Did we change? Note we don't check if the class changed, only if mo changed.
            if pre.get_ava_set("memberof") != tgte.get_ava_set("memberof")
                || pre.get_ava_set("directmemberof") != tgte.get_ava_set("directmemberof")
            {
                // Yes we changed - we now must process all our members, as they need to
                // inherit changes. Some of these members COULD be non groups, but we
                // handle that in the dbload step.
                ltrace!(
                    au,
                    "{:?} changed, flagging members as groups to change. ",
                    guuid
                );
                if let Some(miter) = tgte.get_ava_as_refuuid("member") {
                    group_affect.extend(miter.filter(|m| !other_cache.contains_key(m)));
                };

                // push the entries to pre/cand
                pre_candidates.push(pre);
                candidates.push(tgte);
            } else {
                ltrace!(au, "{:?} stable", guuid);
            }
        }

        debug_assert!(pre_candidates.len() == candidates.len());
        // Write this stripe if populated.
        if !pre_candidates.is_empty() {
            qs.internal_batch_modify(au, pre_candidates, candidates)
                .map_err(|e| {
                    ladmin_error!(au, "Failed to commit memberof group set {:?}", e);
                    e
                })?;
        }
        // Next loop!
    }

    // ALL GROUP MOS + DMOS ARE NOW STABLE. We can load these into other items directly.
    let mut pre_candidates = Vec::with_capacity(other_cache.len());
    let mut candidates = Vec::with_capacity(other_cache.len());

    other_cache
        .into_iter()
        .try_for_each(|(auuid, (pre, mut tgte))| {
            ltrace!(au, "=> processing affected uuid {:?}", auuid);
            debug_assert!(!tgte.attribute_equality("class", &CLASS_GROUP));
            do_memberof(au, qs, &auuid, &mut tgte)?;
            // Only write if a change occured.
            if pre.get_ava_set("memberof") != tgte.get_ava_set("memberof")
                || pre.get_ava_set("directmemberof") != tgte.get_ava_set("directmemberof")
            {
                pre_candidates.push(pre);
                candidates.push(tgte);
            }
            Ok(())
        })?;

    // Turn the other_cache into a write set.
    // Write the batch out in a single stripe.
    qs.internal_batch_modify(au, pre_candidates, candidates)
    // Done! 🎉
}

impl Plugin for MemberOf {
    fn id() -> &'static str {
        "memberof"
    }

    fn post_create(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        let group_affect = cand
            .iter()
            .map(|e| e.get_uuid())
            .chain(
                cand.iter()
                    .filter_map(|e| {
                        // Is it a group?
                        if e.attribute_equality("class", &CLASS_GROUP) {
                            e.get_ava_as_refuuid("member")
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .copied()
            .collect();

        apply_memberof(au, qs, group_affect)
    }

    fn post_modify(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        pre_cand: &[Entry<EntrySealed, EntryCommitted>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // TODO: Limit this to when it's a class, member, mo, dmo change instead.
        let group_affect = cand
            .iter()
            .map(|post| post.get_uuid())
            .chain(
                pre_cand
                    .iter()
                    .filter_map(|pre| {
                        if pre.attribute_equality("class", &CLASS_GROUP) {
                            pre.get_ava_as_refuuid("member")
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .chain(
                cand.iter()
                    .filter_map(|post| {
                        if post.attribute_equality("class", &CLASS_GROUP) {
                            post.get_ava_as_refuuid("member")
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .copied()
            .collect();

        apply_memberof(au, qs, group_affect)
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
        // NOTE: DO NOT purge directmemberof - we use that to restore memberships
        // in recycle revive!
        cand.iter_mut().for_each(|e| e.purge_ava("memberof"));
        Ok(())
    }

    fn post_delete(
        au: &mut AuditScope,
        qs: &QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Similar condition to create - we only trigger updates on groups's members,
        // so that they can find they are no longer a mo of what was deleted.
        let group_affect = cand
            .iter()
            .filter_map(|e| {
                // Is it a group?
                if e.attribute_equality("class", &CLASS_GROUP) {
                    e.get_ava_as_refuuid("member")
                } else {
                    None
                }
            })
            .flatten()
            .copied()
            .collect();

        apply_memberof(au, qs, group_affect)
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
            let filt_in = filter!(f_and!([
                f_eq("class", PartialValue::new_class("group")),
                f_eq("member", PartialValue::new_refer(*e.get_uuid()))
            ]));

            let direct_memberof = match qs
                .internal_search(au, filt_in)
                .map_err(|_| ConsistencyError::QueryServerSearchFailure)
            {
                Ok(d_mo) => d_mo,
                Err(e) => return vec![Err(e)],
            };
            // for all direct -> add uuid to map

            let d_groups_set: ValueSet = direct_memberof
                .iter()
                .map(|e| Value::new_refer(*e.get_uuid()))
                .collect();

            let d_groups_set = if d_groups_set.is_empty() {
                None
            } else {
                Some(d_groups_set)
            };

            ltrace!(
                au,
                "DMO search groups {:?} -> {:?}",
                e.get_uuid(),
                d_groups_set
            );

            match (e.get_ava_set("directmemberof"), d_groups_set) {
                (Some(edmos), Some(dmos)) => {
                    let diff: Vec<_> = dmos.symmetric_difference(edmos).collect();
                    if !diff.is_empty() {
                        ladmin_error!(
                            au,
                            "MemberOfInvalid: Entry {}, DMO has inconsistencies -> {:?}",
                            e,
                            diff
                        );
                        r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                    }
                }
                (None, None) => {
                    // Ok
                }
                _ => {
                    ladmin_error!(
                        au,
                        "MemberOfInvalid directmemberof set and DMO search set differ in size: {}",
                        e.get_uuid()
                    );
                    r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
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
    use crate::modify::{Modify, ModifyList};
    use crate::prelude::*;

    const UUID_A: &'static str = "aaaaaaaa-f82e-4484-a407-181aa03bda5c";
    const UUID_B: &'static str = "bbbbbbbb-2438-4384-9891-48f4c8172e9b";
    const UUID_C: &'static str = "cccccccc-9b01-423f-9ba6-51aa4bbd5dd2";
    const UUID_D: &'static str = "dddddddd-2ab3-48e3-938d-1b4754cd2984";

    const EA: &'static str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_a"],
                "uuid": ["aaaaaaaa-f82e-4484-a407-181aa03bda5c"]
            }
        }"#;

    const EB: &'static str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_b"],
                "uuid": ["bbbbbbbb-2438-4384-9891-48f4c8172e9b"]
            }
        }"#;

    const EC: &'static str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_c"],
                "uuid": ["cccccccc-9b01-423f-9ba6-51aa4bbd5dd2"]
            }
        }"#;

    const ED: &'static str = r#"{
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
            debug!("assert_mo_cands {:?}", cands);
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let mut ed: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());

        ec.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("member", Value::new_refer_s(&UUID_D).unwrap());

        ed.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());

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
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
        let ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_B).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap())),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let ed: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("member", Value::new_refer_s(&UUID_D).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_or!([
                f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap()),
                f_eq("uuid", PartialValue::new_uuids(&UUID_D).unwrap()),
            ])),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_A).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_B).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        ec.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap())),
            ModifyList::new_list(vec![Modify::Removed(
                AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let mut ed: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        ec.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("member", Value::new_refer_s(&UUID_D).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        ed.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq("uuid", PartialValue::new_uuids(&UUID_C).unwrap())),
            ModifyList::new_list(vec![
                Modify::Removed(
                    AttrString::from("member"),
                    PartialValue::new_refer_s(&UUID_A).unwrap()
                ),
                Modify::Removed(
                    AttrString::from("member"),
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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());

        ec.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());

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
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        let mut ed: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(ED);

        ea.add_ava("member", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ea.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());

        eb.add_ava("member", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        eb.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());

        ec.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("member", Value::new_refer_s(&UUID_D).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ec.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());

        ed.add_ava("member", Value::new_refer_s(&UUID_A).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_A).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_B).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_C).unwrap());
        ed.add_ava("memberof", Value::new_refer_s(&UUID_D).unwrap());

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
