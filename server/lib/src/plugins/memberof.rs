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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entry::{Entry, EntryCommitted, EntrySealed};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::value::PartialValue;

pub struct MemberOf;

fn do_group_memberof(
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
        tgte.set_ava_set(&Attribute::DirectMemberOf, dmo.clone());

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
        tgte.set_ava_set(&Attribute::MemberOf, mo);
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

fn do_leaf_memberof(
    qs: &mut QueryServerWriteTransaction,
    all_affected_uuids: BTreeSet<Uuid>,
) -> Result<(), OperationError> {
    trace!("---");

    // We just put everything into the filter here, the query code will remove
    // anything that is a group.
    let all_affected_filter: Vec<_> = all_affected_uuids
        .into_iter()
        .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
        .collect();

    if all_affected_filter.is_empty() {
        trace!("all affected filter is empty, return");
        return Ok(());
    }

    // These are all the affected entries.
    let leaf_entries = qs.internal_search_writeable(&filter!(f_and!([
        f_andnot(f_eq(Attribute::Class, EntryClass::Group.into())),
        FC::Or(all_affected_filter)
    ])))?;

    if leaf_entries.is_empty() {
        trace!("leaf entries empty, return");
        return Ok(());
    }

    let mut leaf_entries: BTreeMap<_, _> = leaf_entries
        .into_iter()
        .map(|entry_tuple| (entry_tuple.0.get_uuid(), entry_tuple))
        .collect();

    let mut changes = Vec::with_capacity(leaf_entries.len());

    // Now that we know which *entries* changed, we actually have to load the groups *again*
    // because the affected entries could still be a DMO/MO of a group that *wasn't* in the
    // change set, and we still need to reflect that they exist.

    let mut groups_or = Vec::with_capacity(leaf_entries.len() * 2);

    for uuid in leaf_entries.keys().copied() {
        groups_or.push(f_eq(Attribute::Member, PartialValue::Refer(uuid)));
        groups_or.push(f_eq(Attribute::DynMember, PartialValue::Refer(uuid)));
    }

    let all_groups = qs
        .internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            FC::Or(groups_or)
        ])))
        .map_err(|err| {
            error!(?err, "internal search failure");
            err
        })?;

    /*
     * Previously we went through the remaining items and processed them one at a time, but
     * that has significant performance limits, since if we update a large dyn group, we then
     * have to perform N searches for each affected member, which may be repeatedly searching
     * for the same groups over and over again.
     *
     * Instead, at this point we know that in memberof application the entire group tree is
     * now stable, and all we need to do is reflect those values into our entries. We can do
     * this in two steps. First we load *all* the groups that relate to our leaf entries that
     * we need to reflect.
     *
     * Then we can go through that in a single pass updating our entries that need to be
     * updated. Since we know that the leaf entries aren't groups, we don't have a collision
     * as a result of using internal_search_writeable.
     */

    // Clear the existing Mo and Dmo on the write stripe.
    for (_pre, tgte) in leaf_entries.values_mut() {
        // Ensure we are MO capable. We only add this if it's not already present.
        tgte.add_ava_if_not_exist(Attribute::Class, EntryClass::MemberOf.into());
        // Clear the dmo + mos, we will recreate them now.
        // This is how we handle deletes/etc.
        tgte.purge_ava(Attribute::MemberOf);
        tgte.purge_ava(Attribute::DirectMemberOf);
    }

    // Now, we go through all the groups, and from each one we update the relevant
    // target entry as needed.
    for group in all_groups {
        trace!(group_id = %group.get_display_id());
        // Our group uuid that we add to direct members.
        let group_uuid = group.get_uuid();

        let memberof_ref = group.get_ava_refer(Attribute::MemberOf);

        let member_ref = group.get_ava_refer(Attribute::Member);
        let dynmember_ref = group.get_ava_refer(Attribute::DynMember);

        let dir_members = member_ref
            .iter()
            .flat_map(|set| set.iter())
            .chain(dynmember_ref.iter().flat_map(|set| set.iter()))
            .copied();

        // These are the entries that are direct members and need to reflect the group
        // as mo and it's mo for indirect mo.
        for dir_member in dir_members {
            if let Some((_pre, tgte)) = leaf_entries.get_mut(&dir_member) {
                trace!(?dir_member, entry_id = ?tgte.get_display_id());
                // We were in the group, lets update.
                if let Some(dmo_set) = tgte.get_ava_refer_mut(Attribute::DirectMemberOf) {
                    dmo_set.insert(group_uuid);
                } else {
                    let dmo = ValueSetRefer::new(group_uuid);
                    tgte.set_ava_set(&Attribute::DirectMemberOf, dmo);
                }

                // We're also in member of this group.
                if let Some(mo_set) = tgte.get_ava_refer_mut(Attribute::MemberOf) {
                    mo_set.insert(group_uuid);
                } else {
                    let mo = ValueSetRefer::new(group_uuid);
                    tgte.set_ava_set(&Attribute::MemberOf, mo);
                }

                // If the group has memberOf attributes, we propogate these to
                // our entry now.
                if let Some(group_mo) = memberof_ref {
                    // IMPORTANT this can't be a NONE because we just create MO in
                    // the step above!
                    if let Some(mo_set) = tgte.get_ava_refer_mut(Attribute::MemberOf) {
                        mo_set.extend(group_mo.iter())
                    }
                }

                if cfg!(debug_assertions) {
                    if let Some(dmo) = group.get_ava_refer(Attribute::DirectMemberOf) {
                        if let Some(mo) = group.get_ava_refer(Attribute::MemberOf) {
                            debug_assert!(mo.is_superset(dmo))
                        }
                    }
                }
            }
            // Done updating that leaf entry.
            // Remember in the None case it could be that the group has a member which *isn't*
            // being altered as a leaf in this operation.
        }
        // Next group.
    }

    // Now only write back leaf entries that actually were changed as a result of the memberof
    // process.
    leaf_entries
        .into_iter()
        .try_for_each(|(auuid, (pre, tgte))| {
            // Only write if a change occurred.
            if pre.get_ava_set(Attribute::MemberOf) != tgte.get_ava_set(Attribute::MemberOf)
                || pre.get_ava_set(Attribute::DirectMemberOf)
                    != tgte.get_ava_set(Attribute::DirectMemberOf)
            {
                trace!("=> processing affected uuid {:?}", auuid);

                if cfg!(debug_assertions) {
                    if let Some(dmo_set) = tgte.get_ava_refer(Attribute::DirectMemberOf) {
                        trace!(?dmo_set);

                        if let Some(mo_set) = tgte.get_ava_refer(Attribute::MemberOf) {
                            trace!(?mo_set);
                            debug_assert!(mo_set.is_superset(dmo_set));
                        } else {
                            unreachable!();
                        }
                    } else {
                        trace!("NONE");
                    };

                    if let Some(pre_dmo_set) = pre.get_ava_refer(Attribute::DirectMemberOf) {
                        trace!(?pre_dmo_set);

                        if let Some(pre_mo_set) = pre.get_ava_refer(Attribute::MemberOf) {
                            trace!(?pre_mo_set);
                            debug_assert!(pre_mo_set.is_superset(pre_dmo_set));
                        } else {
                            unreachable!();
                        }
                    } else {
                        trace!("NONE");
                    };
                };

                changes.push((pre, tgte));
            } else {
                trace!("=> ignoring unmodified uuid {:?}", auuid);
            }
            Ok(())
        })?;

    // Write the batch out in a single stripe.
    qs.internal_apply_writable(changes)
    // Done! 🎉
}

// This is how you know the good code is here.
#[allow(clippy::cognitive_complexity)]
fn apply_memberof(
    qs: &mut QueryServerWriteTransaction,
    // TODO: Experiment with HashSet/BTreeSet here instead of vec.
    // May require https://github.com/rust-lang/rust/issues/62924 to allow popping
    mut affected_uuids: BTreeSet<Uuid>,
) -> Result<(), OperationError> {
    trace!(" => entering apply_memberof");

    // Because of how replication works, we don't send MO over a replication boundary.
    // As a result, we always need to trigger for any changed uuid, so we keep the
    // initial affected set for the leaf resolution.
    //
    // As we proceed, we'll also add the affected members of our groups that are
    // changing.
    let mut all_affected_uuids: BTreeSet<_> = affected_uuids.iter().copied().collect();

    // While there are still affected uuids.
    while !affected_uuids.is_empty() {
        trace!(?affected_uuids);

        // Ignore recycled/tombstones
        let filt = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Group.into()),
            FC::Or(
                affected_uuids
                    .iter()
                    .copied()
                    .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
                    .collect()
            )
        ]));

        // Clear the set for the next iteration
        affected_uuids.clear();

        let work_set = qs.internal_search_writeable(&filt)?;
        let mut changes = Vec::with_capacity(work_set.len());

        for (pre, mut tgte) in work_set.into_iter() {
            let guuid = pre.get_uuid();

            trace!(
                "=> processing group update -> {:?} {}",
                guuid,
                tgte.get_display_id()
            );

            do_group_memberof(qs, guuid, &mut tgte)?;

            // Did we change? Note we don't check if the class changed, only if mo changed.
            if pre.get_ava_set(Attribute::MemberOf) != tgte.get_ava_set(Attribute::MemberOf)
                || pre.get_ava_set(Attribute::DirectMemberOf)
                    != tgte.get_ava_set(Attribute::DirectMemberOf)
            {
                // Yes we changed - we now must process all our members, as they need to
                // inherit changes. Some of these members COULD be non groups, but we
                // handle them in the subsequent steps.
                trace!(
                    "{:?} {} changed, flagging members as groups to change. ",
                    guuid,
                    tgte.get_display_id()
                );

                // Since our groups memberof (and related, direct member of) has changed, we
                // need to propogate these values forward into our members. At this point we
                // mark all our members as being part of the affected set.
                let pre_member = pre.get_ava_refer(Attribute::Member);
                let post_member = tgte.get_ava_refer(Attribute::Member);

                match (pre_member, post_member) {
                    (Some(pre_m), Some(post_m)) => {
                        affected_uuids.extend(pre_m);
                        affected_uuids.extend(post_m);
                    }
                    (Some(members), None) | (None, Some(members)) => {
                        // Doesn't matter what order, just that they are affected
                        affected_uuids.extend(members);
                    }
                    (None, None) => {}
                };

                let pre_dynmember = pre.get_ava_refer(Attribute::DynMember);
                let post_dynmember = tgte.get_ava_refer(Attribute::DynMember);

                match (pre_dynmember, post_dynmember) {
                    (Some(pre_m), Some(post_m)) => {
                        affected_uuids.extend(pre_m);
                        affected_uuids.extend(post_m);
                    }
                    (Some(members), None) | (None, Some(members)) => {
                        // Doesn't matter what order, just that they are affected
                        affected_uuids.extend(members);
                    }
                    (None, None) => {}
                };

                // push the entries to pre/cand
                changes.push((pre, tgte));
            } else {
                // If the group is stable, then we *only* need to update memberof
                // on members that may have been added or removed. This exists to
                // optimise when we add a member to a group, but without changing the
                // group's mo/dmo to save re-writing mo to all the other members.
                //
                // If the group's memberof has been through the unstable state,
                // all our members are already fully loaded into the affected sets.
                //
                // NOTE: This filtering of what members were actually impacted is
                // performed in the call to post_modify_inner.

                trace!("{:?} {} stable", guuid, tgte.get_display_id());
            }
        }

        // Write this stripe if populated.
        if !changes.is_empty() {
            trace!("wrote stripe {}", changes.len());
            qs.internal_apply_writable(changes).map_err(|err| {
                error!(?err, "Failed to commit memberof group set");
                err
            })?;
        }

        // Reflect the full set of affected uuids into our all affected set.
        all_affected_uuids.extend(affected_uuids.iter());

        // Next loop!
        trace!("-------------------------------------");
    }

    // ALL GROUP MOS + DMOS ARE NOW STABLE. We can update oul leaf entries as required.
    do_leaf_memberof(qs, all_affected_uuids)
}

impl Plugin for MemberOf {
    fn id() -> &'static str {
        Attribute::MemberOf.as_ref()
    }

    #[instrument(level = "debug", name = "memberof_post_create", skip_all)]
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
        conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // If a uuid was in a conflict state, it will be present in the cand/pre_cand set,
        // but it *may not* trigger dyn groups as the conflict before and after may satisfy
        // the filter as it exists.
        //
        // In these cases we need to force dynmembers to be reloaded if any conflict occurs
        // to ensure that all our memberships are accurate.
        let force_dyngroup_cand_update = !conflict_uuids.is_empty();

        // IMPORTANT - we need this for now so that dyngroup doesn't error on us, since
        // repl is internal and dyngroup has a safety check to prevent external triggers.
        let ident_internal = Identity::from_internal();
        Self::post_modify_inner(
            qs,
            pre_cand,
            cand,
            &ident_internal,
            force_dyngroup_cand_update,
        )
    }

    #[instrument(level = "debug", name = "memberof_post_modify", skip_all)]
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand, &me.ident, false)
    }

    #[instrument(level = "debug", name = "memberof_post_batch_modify", skip_all)]
    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, pre_cand, cand, &me.ident, false)
    }

    #[instrument(level = "debug", name = "memberof_pre_delete", skip_all)]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidCommitted>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Ensure that when an entry is deleted, that we remove its memberof values,
        // and convert direct memberof to recycled direct memberof.

        for entry in cand.iter_mut() {
            if let Some(direct_mo_vs) = entry.pop_ava(Attribute::DirectMemberOf) {
                entry.set_ava_set(&Attribute::RecycledDirectMemberOf, direct_mo_vs);
            } else {
                // Ensure it's empty
                entry.purge_ava(Attribute::RecycledDirectMemberOf);
            }
            entry.purge_ava(Attribute::MemberOf);
        }

        Ok(())
    }

    #[instrument(level = "debug", name = "memberof_post_delete", skip_all)]
    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Similar condition to create - we only trigger updates on groups's members,
        // so that they can find they are no longer a mo of what was deleted.
        let affected_uuids = cand
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

        apply_memberof(qs, affected_uuids)
    }

    #[instrument(level = "debug", name = "memberof::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        let mut r = Vec::with_capacity(0);

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

            // what groups is this entry a direct member of?
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

            trace!(
                "DMO search groups {:?} -> {:?}",
                e.get_display_id(),
                d_groups_set
            );

            match (e.get_ava_set(Attribute::DirectMemberOf), d_groups_set) {
                (Some(edmos), Some(b)) => {
                    // Can they both be reference sets?
                    match edmos.as_refer_set() {
                        Some(a) => {
                            let diff: Vec<_> = a.symmetric_difference(&b).collect();
                            if !diff.is_empty() {
                                error!(
                                    "MemberOfInvalid: Entry {}, DMO has inconsistencies",
                                    e.get_display_id(),
                                );
                                trace!(entry_direct_member_of = ?a);
                                trace!(expected_direct_groups = ?b);
                                trace!(?diff);

                                r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                            }
                        }
                        _ => {
                            error!("MemberOfInvalid: Entry {}, DMO has incorrect syntax - should be reference uuid set", e.get_display_id());
                            r.push(Err(ConsistencyError::MemberOfInvalid(e.get_id())));
                        }
                    }
                }
                (None, None) => {
                    // Ok
                }
                (entry_direct_member_of, expected_direct_groups) => {
                    error!(
                        "MemberOfInvalid directmemberof set and DMO search set differ in size: {}",
                        e.get_display_id()
                    );
                    // trace!(?e);
                    trace!(?entry_direct_member_of);
                    trace!(?expected_direct_groups);
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

        let affected_uuids = cand
            .iter()
            .map(|e| e.get_uuid())
            .chain(dyngroup_change)
            // In a create, we have to always examine our members as being affected.
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

        apply_memberof(qs, affected_uuids)
    }

    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        ident: &Identity,
        force_dyngroup_cand_update: bool,
    ) -> Result<(), OperationError> {
        let dyngroup_change = super::dyngroup::DynGroup::post_modify(
            qs,
            pre_cand,
            cand,
            ident,
            force_dyngroup_cand_update,
        )?;

        let mut affected_uuids: BTreeSet<_> = cand
            .iter()
            .map(|post| post.get_uuid())
            .chain(dyngroup_change)
            .collect();

        for (pre, post) in pre_cand.iter().zip(cand.iter()).filter(|(pre, post)| {
            post.attribute_equality(Attribute::Class, &EntryClass::Group.into())
                || pre.attribute_equality(Attribute::Class, &EntryClass::Group.into())
        }) {
            let pre_member = pre.get_ava_refer(Attribute::Member);
            let post_member = post.get_ava_refer(Attribute::Member);

            match (pre_member, post_member) {
                (Some(pre_m), Some(post_m)) => {
                    // Show only the *changed* uuids for leaf resolution.
                    affected_uuids.extend(pre_m.symmetric_difference(post_m));
                }
                (Some(members), None) | (None, Some(members)) => {
                    // Doesn't matter what order, just that they are affected
                    affected_uuids.extend(members);
                }
                (None, None) => {}
            };

            let pre_dynmember = pre.get_ava_refer(Attribute::DynMember);
            let post_dynmember = post.get_ava_refer(Attribute::DynMember);

            match (pre_dynmember, post_dynmember) {
                (Some(pre_m), Some(post_m)) => {
                    // Show only the *changed* uuids.
                    affected_uuids.extend(pre_m.symmetric_difference(post_m));
                }
                (Some(members), None) | (None, Some(members)) => {
                    // Doesn't matter what order, just that they are affected
                    affected_uuids.extend(members);
                }
                (None, None) => {}
            };
        }

        apply_memberof(qs, affected_uuids)
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
            assert_eq!(cands.len(), $cand);
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

        let preload = Vec::with_capacity(0);
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

        let preload = Vec::with_capacity(0);
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

        let preload = Vec::with_capacity(0);
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

        let preload = Vec::with_capacity(0);
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                Attribute::Member,
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
                    Attribute::Member,
                    PartialValue::new_refer_s(UUID_A).unwrap()
                ),
                Modify::Removed(
                    Attribute::Member,
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
