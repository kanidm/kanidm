use crate::prelude::*;
use hashbrown::HashMap;
use std::collections::BTreeSet;

use super::profiles::{
    AccessControlModify, AccessControlModifyResolved, AccessControlReceiverCondition,
    AccessControlTargetCondition,
};
use super::AccessResult;
use std::sync::Arc;

pub(super) enum ModifyResult<'a> {
    Denied,
    Grant,
    Allow {
        pres: BTreeSet<&'a str>,
        rem: BTreeSet<&'a str>,
        cls: BTreeSet<&'a str>,
    },
}

pub(super) fn apply_modify_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlModifyResolved],
    sync_agreements: &'a HashMap<Uuid, BTreeSet<String>>,
    entry: &'a Arc<EntrySealedCommitted>,
) -> ModifyResult<'a> {
    let mut denied = false;
    let mut grant = false;
    let mut constrain_pres = BTreeSet::default();
    let mut allow_pres = BTreeSet::default();
    let mut constrain_rem = BTreeSet::default();
    let mut allow_rem = BTreeSet::default();
    let mut constrain_cls = BTreeSet::default();
    let mut allow_cls = BTreeSet::default();

    // Some useful references.
    //  - needed for checking entry manager conditions.
    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    // run each module. These have to be broken down further due to modify
    // kind of being three operations all in one.

    match modify_ident_test(ident) {
        AccessResult::Denied => denied = true,
        AccessResult::Grant => grant = true,
        AccessResult::Ignore => {}
        AccessResult::Constrain(mut set) => constrain_pres.append(&mut set),
        AccessResult::Allow(mut set) => allow_pres.append(&mut set),
    }

    if !grant && !denied {
        // Check with protected if we should proceed.

        // If it's a sync entry, constrain it.
        match modify_sync_constrain(ident, entry, sync_agreements) {
            AccessResult::Denied => denied = true,
            AccessResult::Constrain(mut set) => {
                constrain_rem.extend(set.iter().copied());
                constrain_pres.append(&mut set)
            }
            // Can't grant.
            AccessResult::Grant |
            // Can't allow
            AccessResult::Allow(_) |
            AccessResult::Ignore => {}
        }

        // Setup the acp's here
        let scoped_acp: Vec<&AccessControlModify> = related_acp
            .iter()
            .filter_map(|acm| {
                match &acm.receiver_condition {
                    AccessControlReceiverCondition::GroupChecked => {
                        // The groups were already checked during filter resolution. Trust
                        // that result, and continue.
                    }
                    AccessControlReceiverCondition::EntryManager => {
                        // This condition relies on the entry we are looking at to have a back-ref
                        // to our uuid or a group we are in as an entry manager.

                        // Note, while schema has this as single value, we currently
                        // fetch it as a multivalue btreeset for future incase we allow
                        // multiple entry manager by in future.
                        if let Some(entry_manager_uuids) =
                            entry.get_ava_refer(Attribute::EntryManagedBy)
                        {
                            let group_check = ident_memberof
                                // Have at least one group allowed.
                                .map(|imo| imo.intersection(entry_manager_uuids).next().is_some())
                                .unwrap_or_default();

                            let user_check = ident_uuid
                                .map(|u| entry_manager_uuids.contains(&u))
                                .unwrap_or_default();

                            if !(group_check || user_check) {
                                // Not the entry manager
                                return None;
                            }
                        } else {
                            // Can not satisfy.
                            return None;
                        }
                    }
                };

                match &acm.target_condition {
                    AccessControlTargetCondition::Scope(f_res) => {
                        if !entry.entry_match_no_index(f_res) {
                            debug!(entry = ?entry.get_display_id(), acm = %acm.acp.acp.name, "entry DOES NOT match acs");
                            return None;
                        }
                    }
                };

                debug!(entry = ?entry.get_display_id(), acs = %acm.acp.acp.name, "acs applied to entry");

                Some(acm.acp)
            })
            .collect();

        match modify_pres_test(scoped_acp.as_slice()) {
            AccessResult::Denied => denied = true,
            // Can never return a unilateral grant.
            AccessResult::Grant => {}
            AccessResult::Ignore => {}
            AccessResult::Constrain(mut set) => constrain_pres.append(&mut set),
            AccessResult::Allow(mut set) => allow_pres.append(&mut set),
        }

        match modify_rem_test(scoped_acp.as_slice()) {
            AccessResult::Denied => denied = true,
            // Can never return a unilateral grant.
            AccessResult::Grant => {}
            AccessResult::Ignore => {}
            AccessResult::Constrain(mut set) => constrain_rem.append(&mut set),
            AccessResult::Allow(mut set) => allow_rem.append(&mut set),
        }

        match modify_cls_test(scoped_acp.as_slice()) {
            AccessResult::Denied => denied = true,
            // Can never return a unilateral grant.
            AccessResult::Grant => {}
            AccessResult::Ignore => {}
            AccessResult::Constrain(mut set) => constrain_cls.append(&mut set),
            AccessResult::Allow(mut set) => allow_cls.append(&mut set),
        }
    }

    if denied {
        ModifyResult::Denied
    } else if grant {
        ModifyResult::Grant
    } else {
        let allowed_pres = if !constrain_pres.is_empty() {
            // bit_and
            &constrain_pres & &allow_pres
        } else {
            allow_pres
        };

        let allowed_rem = if !constrain_rem.is_empty() {
            // bit_and
            &constrain_rem & &allow_rem
        } else {
            allow_rem
        };

        let allowed_cls = if !constrain_cls.is_empty() {
            // bit_and
            &constrain_cls & &allow_cls
        } else {
            allow_cls
        };

        ModifyResult::Allow {
            pres: allowed_pres,
            rem: allowed_rem,
            cls: allowed_cls,
        }
    }
}

fn modify_ident_test<'a>(ident: &Identity) -> AccessResult<'a> {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return AccessResult::Grant;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return AccessResult::Denied;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for modify event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to modify");
            return AccessResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    AccessResult::Ignore
}

fn modify_pres_test<'a>(scoped_acp: &[&'a AccessControlModify]) -> AccessResult<'a> {
    let allowed_pres: BTreeSet<&str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.presattrs.iter().map(|v| v.as_str()))
        .collect();
    AccessResult::Allow(allowed_pres)
}

fn modify_rem_test<'a>(scoped_acp: &[&'a AccessControlModify]) -> AccessResult<'a> {
    let allowed_rem: BTreeSet<&str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.remattrs.iter().map(|v| v.as_str()))
        .collect();
    AccessResult::Allow(allowed_rem)
}

fn modify_cls_test<'a>(scoped_acp: &[&'a AccessControlModify]) -> AccessResult<'a> {
    let allowed_classes: BTreeSet<&str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.classes.iter().map(|v| v.as_str()))
        .collect();
    AccessResult::Allow(allowed_classes)
}

fn modify_sync_constrain<'a>(
    ident: &Identity,
    entry: &'a Arc<EntrySealedCommitted>,
    sync_agreements: &'a HashMap<Uuid, BTreeSet<String>>,
) -> AccessResult<'a> {
    match &ident.origin {
        IdentType::Internal => AccessResult::Ignore,
        IdentType::Synch(_) => {
            // Allowed to mod sync objects. Later we'll probably need to check the limits of what
            // it can do if we go that way.
            AccessResult::Ignore
        }
        IdentType::User(_) => {
            // We need to meet these conditions.
            // * We are a sync object
            // * We have a sync_parent_uuid
            let is_sync = entry
                .get_ava_set(Attribute::Class)
                .map(|classes| classes.contains(&EntryClass::SyncObject.into()))
                .unwrap_or(false);

            if !is_sync {
                return AccessResult::Ignore;
            }

            if let Some(sync_uuid) = entry.get_ava_single_refer(Attribute::SyncParentUuid) {
                let mut set = btreeset![
                    Attribute::UserAuthTokenSession.as_ref(),
                    Attribute::OAuth2Session.as_ref(),
                    Attribute::OAuth2ConsentScopeMap.as_ref(),
                    Attribute::CredentialUpdateIntentToken.as_ref()
                ];

                if let Some(sync_yield_authority) = sync_agreements.get(&sync_uuid) {
                    set.extend(sync_yield_authority.iter().map(|s| s.as_str()))
                }

                AccessResult::Constrain(set)
            } else {
                warn!(entry = ?entry.get_uuid(), "sync_parent_uuid not found on sync object, preventing all access");
                AccessResult::Denied
            }
        }
    }
}
