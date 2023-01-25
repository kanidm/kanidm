use super::profiles::AccessControlCreate;
use crate::filter::FilterValidResolved;
use crate::prelude::*;
use std::collections::BTreeSet;

pub(super) enum CreateResult {
    Denied,
    Grant,
}

enum IResult {
    Denied,
    Grant,
    Ignore,
}

pub(super) fn apply_create_access<'a>(
    ident: &Identity,
    related_acp: &'a [(&AccessControlCreate, Filter<FilterValidResolved>)],
    entry: &'a Entry<EntryInit, EntryNew>,
) -> CreateResult {
    let mut denied = false;
    let mut grant = false;

    match create_filter_entry(ident, related_acp, entry) {
        IResult::Denied => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
    }

    if denied {
        // Something explicitly said no.
        CreateResult::Denied
    } else if grant {
        // Something said yes
        CreateResult::Grant
    } else {
        // Nothing said yes.
        CreateResult::Denied
    }
}

fn create_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [(&AccessControlCreate, Filter<FilterValidResolved>)],
    entry: &'a Entry<EntryInit, EntryNew>,
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
    info!(event = %ident, "Access check for create event");

    match ident.access_scope() {
        AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to create");
            return IResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    // Build the set of requested classes and attrs here.
    let create_attrs: BTreeSet<&str> = entry.get_ava_names().collect();
    // If this is empty, we make an empty set, which is fine because
    // the empty class set despite matching is_subset, will have the
    // following effect:
    // * there is no class on entry, so schema will fail
    // * plugin-base will add object to give a class, but excess
    //   attrs will cause fail (could this be a weakness?)
    // * class is a "may", so this could be empty in the rules, so
    //   if the accr is empty this would not be a true subset,
    //   so this would "fail", but any content in the accr would
    //   have to be validated.
    //
    // I still think if this is None, we should just fail here ...
    // because it shouldn't be possible to match.

    let create_classes: BTreeSet<&str> = match entry.get_ava_iter_iutf8("class") {
        Some(s) => s.collect(),
        None => {
            admin_error!("Class set failed to build - corrupted entry?");
            return IResult::Denied;
        }
    };

    //      Find the set of related acps for this entry.
    //
    //      For each "created" entry.
    //          If the created entry is 100% allowed by this acp
    //          IE: all attrs to be created AND classes match classes
    //              allow
    //          if no acp allows, fail operation.
    let allow = related_acp.iter().any(|(accr, f_res)| {
        // Check to see if allowed.
        if entry.entry_match_no_index(f_res) {
            security_access!(?entry, acs = ?accr, "entry matches acs");
            // It matches, so now we have to check attrs and classes.
            // Remember, we have to match ALL requested attrs
            // and classes to pass!
            let allowed_attrs: BTreeSet<&str> = accr.attrs.iter().map(|s| s.as_str()).collect();
            let allowed_classes: BTreeSet<&str> = accr.classes.iter().map(|s| s.as_str()).collect();

            if !create_attrs.is_subset(&allowed_attrs) {
                security_access!("create_attrs is not a subset of allowed");
                security_access!("{:?} !⊆ {:?}", create_attrs, allowed_attrs);
                return false;
            }
            if !create_classes.is_subset(&allowed_classes) {
                security_access!("create_classes is not a subset of allowed");
                security_access!("{:?} !⊆ {:?}", create_classes, allowed_classes);
                return false;
            }
            security_access!("passed");

            true
        } else {
            trace!(?entry, acs = %accr.acp.name, "entry DOES NOT match acs");
            // Does not match, fail this rule.
            false
        }
    });

    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}
