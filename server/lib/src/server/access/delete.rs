use super::profiles::AccessControlDelete;
use crate::filter::FilterValidResolved;
use crate::prelude::*;
use std::sync::Arc;

pub(super) enum DeleteResult {
    Denied,
    Grant,
}

enum IResult {
    Denied,
    Grant,
    Ignore,
}

pub(super) fn apply_delete_access<'a>(
    ident: &Identity,
    related_acp: &'a [(&AccessControlDelete, Filter<FilterValidResolved>)],
    entry: &'a Arc<EntrySealedCommitted>,
) -> DeleteResult {
    let mut denied = false;
    let mut grant = false;

    match protected_filter_entry(ident, entry) {
        IResult::Denied => denied = true,
        IResult::Grant | IResult::Ignore => {}
    }

    match delete_filter_entry(ident, related_acp, entry) {
        IResult::Denied => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
    }

    if denied {
        // Something explicitly said no.
        DeleteResult::Denied
    } else if grant {
        // Something said yes
        DeleteResult::Grant
    } else {
        // Nothing said yes.
        DeleteResult::Denied
    }
}

fn delete_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [(&AccessControlDelete, Filter<FilterValidResolved>)],
    entry: &'a Arc<EntrySealedCommitted>,
) -> IResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return IResult::Grant;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return IResult::Denied;
        }
        IdentType::User(_) => {}
    };
    info!(event = %ident, "Access check for delete event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to delete");
            return IResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    let allow = related_acp.iter().any(|(acd, f_res)| {
        if entry.entry_match_no_index(f_res) {
            security_access!(
                entry_uuid = ?entry.get_uuid(),
                acs = %acd.acp.name,
                "entry matches acs"
            );
            // It matches, so we can delete this!
            security_access!("passed");
            true
        } else {
            trace!(
                "entry {:?} DOES NOT match acs {}",
                entry.get_uuid(),
                acd.acp.name
            );
            // Does not match, fail.
            false
        } // else
    }); // any related_acp
    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}

fn protected_filter_entry(ident: &Identity, entry: &Arc<EntrySealedCommitted>) -> IResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, protected rules do not apply.");
            IResult::Ignore
        }
        IdentType::Synch(_) => {
            security_access!("sync agreements may not directly delete entities");
            IResult::Denied
        }
        IdentType::User(_) => {
            // Now check things ...

            // For now we just block create on sync object
            if let Some(classes) = entry.get_ava_set("class") {
                if classes.contains(&PVCLASS_SYNC_OBJECT) {
                    // Block the mod
                    security_access!("attempt to delete with protected class type");
                    IResult::Denied
                } else {
                    IResult::Ignore
                }
            } else {
                // Nothing to check.
                IResult::Ignore
            }
        }
    }
}
