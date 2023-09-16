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

use std::collections::BTreeSet;
use std::sync::Arc;

use hashbrown::HashMap;
use kanidm_proto::v1::{ConsistencyError, OperationError};

use crate::entry::{Entry, EntryCommitted, EntrySealed, EntryTuple};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::value::PartialValue;

pub struct MemberOf;

fn do_memberof(
    qs: &mut QueryServerWriteTransaction,
    uuid: Uuid,
    tgte: &mut EntryInvalidCommitted,
) -> Result<(), OperationError> {
    //  search where we are member
    let groups = qs
        .internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            f_or!([
                f_eq(Attribute::Member, PartialValue::Refer(uuid)),
                f_eq(Attribute::DynMember, PartialValue::Refer(uuid))
            ])
        ])))
        .map_err(|e| {
            admin_error!("internal search failure -> {:?}", e);
            e
        })?;

    // Ensure we are MO capable. We only add this if it's not already present.
    tgte.add_ava_if_not_exist(Attribute::Class, EntryClass::MemberOf.into());
    // Clear the dmo + mos, we will recreate them now.
    // This is how we handle deletes/etc.
    tgte.purge_ava(Attribute::MemberOf);
    tgte.purge_ava(Attribute::DirectMemberOf);

    // What are our direct and indirect mos?
    let dmo = ValueSetRefer::from_iter(groups.iter().map(|g| g.get_uuid()));

    let mut mo = ValueSetRefer::from_iter(
        groups
            .iter()
            .filter_map(|g| {
                g.get_ava_set(Attribute::MemberOf)
                    .and_then(|s| s.as_refer_set())
                    .map(|s| s.iter())
            })
            .flatten()
            .copied(),
    );

    // Add all the direct mo's and mos.
    if let Some(dmo) = dmo {
        // We need to clone this else type checker gets real sad.
        tgte.set_ava_set(Attribute::DirectMemberOf, dmo.clone());

        if let Some(mo) = &mut mo {
            let dmo = dmo as ValueSet;
            mo.merge(&dmo)?;
        } else {
            // Means MO is empty, so we need to duplicate dmo to allow things to
            // proceed.
            mo = Some(dmo);
        };
    };

    if let Some(mo) = mo {
        tgte.set_ava_set(Attribute::MemberOf, mo);
    }

    trace!(
        "Updating {:?} to be dir mo {:?}",
        uuid,
        tgte.get_ava_set(Attribute::DirectMemberOf)
    );
    trace!(
        "Updating {:?} to be mo {:?}",
        uuid,
        tgte.get_ava_set(Attribute::MemberOf)
    );
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
fn apply_memberof(
    qs: &mut QueryServerWriteTransaction,
    // TODO: Experiment with HashSet/BTreeSet here instead of vec.
    // May require https://github.com/rust-lang/rust/issues/62924 to allow popping
    mut group_affect: Vec<Uuid>,
) -> Result<(), OperationError> {
    trace!(" => entering apply_memberof");
    trace!(" => initial group_affect {:?}", group_affect);

    // We can't cache groups, because we need to be continually writing
    // and querying them. But we can cache anything we find in the process
    // to speed up the later other_affect write op, and we can use this
    // to avoid loading things that aren't groups.
    // All other changed entries (mo, dmo cleared)
    let mut other_cache: HashMap<Uuid, EntryTuple> = HashMap::with_capacity(group_affect.len() * 2);
    while !group_affect.is_empty() {
        group_affect.sort();
        group_affect.dedup();

        // Ignore recycled/tombstones
        let filt = filter!(FC::Or(
            group_affect
                .drain(0..)
                .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                .collect()
        ));

        let work_set = qs.internal_search_writeable(&filt)?;
        // Load the vecdeque with this batch.

        let mut changes = Vec::with_capacity(work_set.len());

        for (pre, mut tgte) in work_set.into_iter() {
            let guuid = pre.get_uuid();
            // load the entry from the db.
            if !tgte.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                // It's not a group, we'll deal with you later. We should NOT
                // have seen this UUID before, as either we are on the first
                // iteration OR the checks belowe should have filtered it out.
                trace!("not a group, delaying update to -> {:?}", guuid);
                other_cache.insert(guuid, (pre, tgte));
                continue;
            }

            trace!("=> processing group update -> {:?}", guuid);

            do_memberof(qs, guuid, &mut tgte)?;

            // Did we change? Note we don't check if the class changed, only if mo changed.
            if pre.get_ava_set(Attribute::MemberOf) != tgte.get_ava_set(Attribute::MemberOf)
                || pre.get_ava_set(Attribute::DirectMemberOf)
                    != tgte.get_ava_set(Attribute::DirectMemberOf)
            {
                // Yes we changed - we now must process all our members, as they need to
                // inherit changes. Some of these members COULD be non groups, but we
                // handle that in the dbload step.
                trace!(
                    "{:?} changed, flagging members as groups to change. ",
                    guuid
                );
                if let Some(miter) = tgte.get_ava_as_refuuid(Attribute::Member) {
                    group_affect.extend(miter.filter(|m| !other_cache.contains_key(m)));
                };
                if let Some(miter) = tgte.get_ava_as_refuuid(Attribute::DynMember) {
                    group_affect.extend(miter.filter(|m| !other_cache.contains_key(m)));
                };

                // push the entries to pre/cand
                changes.push((pre, tgte));
            } else {
                trace!("{:?} stable", guuid);
            }
        }

        // Write this stripe if populated.
        if !changes.is_empty() {
            qs.internal_apply_writable(changes).map_err(|e| {
                admin_error!("Failed to commit memberof group set {:?}", e);
                e
            })?;
        }
        // Next loop!
    }

    // ALL GROUP MOS + DMOS ARE NOW STABLE. We can load these into other items directly.
    let mut changes = Vec::with_capacity(other_cache.len());

    other_cache
        .into_iter()
        .try_for_each(|(auuid, (pre, mut tgte))| {
            trace!("=> processing affected uuid {:?}", auuid);
            debug_assert!(!tgte.attribute_equality(Attribute::Class, &EntryClass::Group.into()));
            do_memberof(qs, auuid, &mut tgte)?;
            // Only write if a change occurred.
            if pre.get_ava_set(Attribute::MemberOf) != tgte.get_ava_set(Attribute::MemberOf)
                || pre.get_ava_set(Attribute::DirectMemberOf)
                    != tgte.get_ava_set(Attribute::DirectMemberOf)
            {
                changes.push((pre, tgte));
            }
            Ok(())
        })?;

    // Turn the other_cache into a write set.
    // Write the batch out in a single stripe.
    qs.internal_apply_writable(changes)
    // Done! 🎉
}

impl Plugin for MemberOf {
    fn id() -> &'static str {
        Attribute::MemberOf.as_ref()
    }

    #[instrument(level = "debug", name = "memberof_post_create", skip(qs, cand, ce))]
    fn post_create(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::post_create_inner(qs, cand, &ce.ident)
    }

    #[instrument(level = "debug", name = "memberof_post_repl_refresh", skip_all)]
    fn post_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
    ) -> Result<(), OperationError> {
        let ident = Identity::from_internal();
        Self::post_create_inner(qs, cand, &ident)
    }

    #[instrument(level = "debug", name = "memberof_post_repl_incremental", skip_all)]
    fn post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        _conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // IMPORTANT - we need this for now so that dyngroup doesn't error on us, since
        // repl is internal and dyngroup has a safety check to prevent external triggers.
        let ident_internal = Identity::from_internal();
        Self::post_modify_inner(qs, pre_cand, cand, &ident_internal)
    }

    #[instrument(level = "debug", name = "memberof_post_modify", skip_all)]
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand, &me.ident)
    }

    #[instrument(level = "debug", name = "memberof_post_batch_modify", skip_all)]
    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand, &me.ident)
    }

    #[instrument(level = "debug", name = "memberof_post_delete", skip(qs, cand, _de))]
    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Similar condition to create - we only trigger updates on groups's members,
        // so that they can find they are no longer a mo of what was deleted.
        let group_affect = cand
            .iter()
            .filter_map(|e| {
                // Is it a group?
                if e.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                    e.get_ava_as_refuuid(Attribute::Member)
                } else {
                    None
                }
            })
            .flatten()
            .chain(
                // Or a dyn group?
                cand.iter()
                    .filter_map(|post| {
                        if post.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into()) {
                            post.get_ava_as_refuuid(Attribute::DynMember)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .collect();

        apply_memberof(qs, group_affect)
    }

    #[instrument(level = "debug", name = "memberof::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        let mut r = Vec::new();

        let filt_in = filter!(f_pres(Attribute::Class));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        // for each entry in the DB (live).
        for e in all_cand {
            let uuid = e.get_uuid();
            let filt_in = filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::Group.into()),
                f_or!([
                    f_eq(Attribute::Member, PartialValue::Refer(uuid)),
                    f_eq(Attribute::DynMember, PartialValue::Refer(uuid))
                ])
            ]));

            let direct_memberof = match qs
                .internal_search(filt_in)
                .map_err(|_| ConsistencyError::QueryServerSearchFailure)
            {
                Ok(d_mo) => d_mo,
                Err(e) => return vec![Err(e)],
            };
            // for all direct -> add uuid to map

            let d_groups_set: BTreeSet<Uuid> =
                direct_memberof.iter().map(|e| e.get_uuid()).collect();

            let d_groups_set = if d_groups_set.is_empty() {
                None
            } else {
                Some(d_groups_set)
            };

            trace!("DMO search groups {:?} -> {:?}", e.get_uuid(), d_groups_set);

            match (e.get_ava_set(Attribute::DirectMemberOf), d_groups_set) {
                (Some(edmos), Some(b)) => {
                    // Can they both be reference sets?
                    match edmos.as_refer_set() {
                        Some(a) => {
                            let diff: Vec<_> = a.symmetric_difference(&b).collect();
                            if !diff.is_empty() {
                                admin_error!(
                                    "MemberOfInvalid: Entry {}, DMO has inconsistencies -> {:?}",
                                    e,
                                    diff
                                );
                                r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                            }
                        }
                        _ => {
                            admin_error!("MemberOfInvalid: Entry {}, DMO has incorrect syntax", e,);
                            r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                        }
                    }
                }
                (None, None) => {
                    // Ok
                }
                _ => {
                    admin_error!(
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

impl MemberOf {
    fn post_create_inner(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ident: &Identity,
    ) -> Result<(), OperationError> {
        let dyngroup_change = super::dyngroup::DynGroup::post_create(qs, cand, ident)?;

        let group_affect = cand
            .iter()
            .map(|e| e.get_uuid())
            .chain(dyngroup_change)
            .chain(
                cand.iter()
                    .filter_map(|e| {
                        // Is it a group?
                        if e.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                            e.get_ava_as_refuuid(Attribute::Member)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .collect();

        apply_memberof(qs, group_affect)
    }

    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        ident: &Identity,
    ) -> Result<(), OperationError> {
        let dyngroup_change = super::dyngroup::DynGroup::post_modify(qs, pre_cand, cand, ident)?;

        // TODO: Limit this to when it's a class, member, mo, dmo change instead.
        let group_affect = cand
            .iter()
            .map(|post| post.get_uuid())
            .chain(dyngroup_change)
            .chain(
                pre_cand
                    .iter()
                    .filter_map(|pre| {
                        if pre.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                            pre.get_ava_as_refuuid(Attribute::Member)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .chain(
                cand.iter()
                    .filter_map(|post| {
                        if post.attribute_equality(Attribute::Class, &EntryClass::Group.into()) {
                            post.get_ava_as_refuuid(Attribute::Member)
                        } else {
                            None
                        }
                    })
                    .flatten(),
            )
            .collect();

        apply_memberof(qs, group_affect)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    const UUID_A: &str = "aaaaaaaa-f82e-4484-a407-181aa03bda5c";
    const UUID_B: &str = "bbbbbbbb-2438-4384-9891-48f4c8172e9b";
    const UUID_C: &str = "cccccccc-9b01-423f-9ba6-51aa4bbd5dd2";
    const UUID_D: &str = "dddddddd-2ab3-48e3-938d-1b4754cd2984";

    const EA: &str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_a"],
                "uuid": ["aaaaaaaa-f82e-4484-a407-181aa03bda5c"]
            }
        }"#;

    const EB: &str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_b"],
                "uuid": ["bbbbbbbb-2438-4384-9891-48f4c8172e9b"]
            }
        }"#;

    const EC: &str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_c"],
                "uuid": ["cccccccc-9b01-423f-9ba6-51aa4bbd5dd2"]
            }
        }"#;

    const ED: &str = r#"{
            "attrs": {
                "class": ["group", "memberof"],
                "name": ["testgroup_d"],
                "uuid": ["dddddddd-2ab3-48e3-938d-1b4754cd2984"]
            }
        }"#;

    macro_rules! assert_memberof_int {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr,
            $mo:expr,
            $cand:expr
        ) => {{
            let filt = filter!(f_and!([
                f_eq(Attribute::Uuid, PartialValue::new_uuid_s($ea).unwrap()),
                f_eq($mo, PartialValue::new_refer_s($eb).unwrap())
            ]));
            let cands = $qs.internal_search(filt).expect("Internal search failure");
            debug!("assert_mo_cands {:?}", cands);
            assert!(cands.len() == $cand);
        }};
    }

    macro_rules! assert_memberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::MemberOf, 1);
        }};
    }

    macro_rules! assert_dirmemberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::DirectMemberOf, 1);
        }};
    }

    macro_rules! assert_not_memberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::MemberOf, 0);
        }};
    }

    macro_rules! assert_not_dirmemberof {
        (
            $qs:expr,
            $ea:expr,
            $eb:expr
        ) => {{
            assert_memberof_int!($qs, $ea, $eb, Attribute::DirectMemberOf, 0);
        }};
    }

    #[test]
    fn test_create_mo_single() {
        // A -> B
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_create_mo_nested() {
        // A -> B -> C
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb, ec];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                // This is due to nestig, C should be MO both!
                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb, ec];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());

        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_D).unwrap());

        ed.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());

        let preload = Vec::new();
        let create = vec![ea, eb, ec, ed];
        run_create_test!(
            Ok(()),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);
                assert_memberof!(qs, UUID_B, UUID_D);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);
                assert_memberof!(qs, UUID_C, UUID_D);

                assert_memberof!(qs, UUID_D, UUID_A);
                assert_memberof!(qs, UUID_D, UUID_B);
                assert_memberof!(qs, UUID_D, UUID_C);
                assert_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_D, UUID_B);
                assert_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
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
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s(UUID_B).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
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

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s(UUID_B).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_B).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s(UUID_C).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_C).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s(UUID_A).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_D).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_or!([
                f_eq(Attribute::Uuid, PartialValue::new_uuid_s(UUID_C).unwrap()),
                f_eq(Attribute::Uuid, PartialValue::new_uuid_s(UUID_D).unwrap()),
            ])),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member.into(),
                Value::new_refer_s(UUID_A).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_B);
                assert_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_memberof!(qs, UUID_B, UUID_B);
                assert_memberof!(qs, UUID_B, UUID_C);
                assert_memberof!(qs, UUID_B, UUID_D);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_memberof!(qs, UUID_C, UUID_C);
                assert_memberof!(qs, UUID_C, UUID_D);

                assert_memberof!(qs, UUID_D, UUID_A);
                assert_memberof!(qs, UUID_D, UUID_B);
                assert_memberof!(qs, UUID_D, UUID_C);
                assert_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_D, UUID_B);
                assert_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        let preload = vec![ea, eb];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member.into(),
                PartialValue::new_refer_s(UUID_B).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member.into(),
                PartialValue::new_refer_s(UUID_B).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_B).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member.into(),
                PartialValue::new_refer_s(UUID_C).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_not_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        let preload = vec![ea, eb, ec];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_C).unwrap()
            )),
            ModifyList::new_list(vec![Modify::Removed(
                Attribute::Member.into(),
                PartialValue::new_refer_s(UUID_A).unwrap()
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_D).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        ed.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_C).unwrap()
            )),
            ModifyList::new_list(vec![
                Modify::Removed(
                    Attribute::Member.into(),
                    PartialValue::new_refer_s(UUID_A).unwrap()
                ),
                Modify::Removed(
                    Attribute::Member.into(),
                    PartialValue::new_refer_s(UUID_D).unwrap()
                ),
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);
                assert_memberof!(qs, UUID_B, UUID_D);

                assert_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);
                assert_memberof!(qs, UUID_C, UUID_D);

                assert_not_memberof!(qs, UUID_D, UUID_A);
                assert_not_memberof!(qs, UUID_D, UUID_B);
                assert_not_memberof!(qs, UUID_D, UUID_C);
                assert_not_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);
                assert_not_dirmemberof!(qs, UUID_B, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_D, UUID_B);
                assert_not_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
            }
        );
    }

    #[test]
    fn test_delete_mo_simple() {
        // X -> B
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        let preload = vec![ea, eb];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
            }
        );
    }

    #[test]
    fn test_delete_mo_nested_head() {
        // X -> B -> C
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
            }
        );
    }

    #[test]
    fn test_delete_mo_nested_branch() {
        // A -> X -> C
        let mut ea: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EA);

        let mut eb: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EB);

        let mut ec: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(EC);

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_B).unwrap()
            )),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_not_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_not_dirmemberof!(qs, UUID_A, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());

        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());

        let preload = vec![ea, eb, ec];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_A).unwrap()
            )),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_B, UUID_A);
                assert_not_memberof!(qs, UUID_B, UUID_B);
                assert_not_memberof!(qs, UUID_B, UUID_C);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);

                assert_not_dirmemberof!(qs, UUID_B, UUID_A);
                assert_not_dirmemberof!(qs, UUID_B, UUID_B);
                assert_not_dirmemberof!(qs, UUID_B, UUID_C);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
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

        ea.add_ava(Attribute::Member, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ea.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());

        eb.add_ava(Attribute::Member, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        eb.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());

        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::Member, Value::new_refer_s(UUID_D).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ec.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());

        ed.add_ava(Attribute::Member, Value::new_refer_s(UUID_A).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_A).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_B).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_C).unwrap());
        ed.add_ava(Attribute::MemberOf, Value::new_refer_s(UUID_D).unwrap());

        let preload = vec![ea, eb, ec, ed];
        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::new_uuid_s(UUID_B).unwrap()
            )),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                //                      V-- this uuid is
                //                                  V-- memberof this UUID
                assert_not_memberof!(qs, UUID_A, UUID_B);
                assert_not_memberof!(qs, UUID_A, UUID_A);
                assert_memberof!(qs, UUID_A, UUID_C);
                assert_memberof!(qs, UUID_A, UUID_D);

                assert_not_memberof!(qs, UUID_C, UUID_A);
                assert_not_memberof!(qs, UUID_C, UUID_B);
                assert_not_memberof!(qs, UUID_C, UUID_C);
                assert_not_memberof!(qs, UUID_C, UUID_D);

                assert_not_memberof!(qs, UUID_D, UUID_A);
                assert_not_memberof!(qs, UUID_D, UUID_B);
                assert_memberof!(qs, UUID_D, UUID_C);
                assert_not_memberof!(qs, UUID_D, UUID_D);

                assert_not_dirmemberof!(qs, UUID_A, UUID_A);
                assert_not_dirmemberof!(qs, UUID_A, UUID_B);
                assert_dirmemberof!(qs, UUID_A, UUID_C);
                assert_dirmemberof!(qs, UUID_A, UUID_D);

                assert_not_dirmemberof!(qs, UUID_C, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_not_dirmemberof!(qs, UUID_C, UUID_C);
                assert_not_dirmemberof!(qs, UUID_C, UUID_D);

                assert_not_dirmemberof!(qs, UUID_D, UUID_A);
                assert_not_dirmemberof!(qs, UUID_C, UUID_B);
                assert_dirmemberof!(qs, UUID_D, UUID_C);
                assert_not_dirmemberof!(qs, UUID_D, UUID_D);
            }
        );
    }
}
