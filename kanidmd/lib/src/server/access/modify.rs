use crate::prelude::*;
use std::collections::BTreeSet;

use super::profiles::AccessControlModify;
use super::AccessResult;
use crate::filter::FilterValidResolved;
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
    related_acp: &'a [(&AccessControlModify, Filter<FilterValidResolved>)],
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
        // Setup the acp's here
        let scoped_acp: Vec<&AccessControlModify> = related_acp
            .iter()
            .filter_map(|(acm, f_res)| {
                if entry.entry_match_no_index(f_res) {
                    Some(*acm)
                } else {
                    None
                }
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
    info!(event = %ident, "Access check for modify event");

    match ident.access_scope() {
        AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::Synchronise => {
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
