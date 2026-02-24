use super::migration::{migration_entry_attrs, MIGRATION_ENTRY_CLASSES, MIGRATION_IGNORE_CLASSES};
use super::profiles::{
    AccessControlCreateResolved, AccessControlReceiverCondition, AccessControlTargetCondition,
};
use super::protected::{PROTECTED_ENTRY_CLASSES, PROTECTED_MOD_PRES_ENTRY_CLASSES};
use crate::prelude::*;
use std::collections::BTreeSet;
use std::ops::Sub;

pub(super) enum CreateResult<'a> {
    Deny,
    Grant,
    Allow {
        pres: BTreeSet<Attribute>,
        pres_cls: BTreeSet<&'a str>,
    },
}

enum IResult<'a> {
    Deny,
    Grant,
    Ignore,
    Allow {
        pres: BTreeSet<Attribute>,
        pres_cls: BTreeSet<&'a str>,
    },
}

pub(super) fn apply_create_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlCreateResolved],
    entry: &'a Entry<EntryInit, EntryNew>,
) -> CreateResult<'a> {
    let mut denied = false;
    let mut grant = false;

    let constrain_pres = BTreeSet::default();
    let mut allow_pres = BTreeSet::default();

    let constrain_pres_cls = BTreeSet::default();
    let mut allow_pres_cls = BTreeSet::default();

    // This module can never yield a grant.
    match protected_filter_entry(ident, entry) {
        IResult::Deny => denied = true,
        IResult::Grant | IResult::Ignore | IResult::Allow { .. } => {}
    }

    match migration_filter_entry(ident, entry) {
        IResult::Deny => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
        IResult::Allow {
            mut pres,
            mut pres_cls,
        } => {
            allow_pres.append(&mut pres);
            allow_pres_cls.append(&mut pres_cls);
        }
    }

    match create_filter_entry(ident, related_acp, entry) {
        IResult::Deny => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
        IResult::Allow {
            mut pres,
            mut pres_cls,
        } => {
            allow_pres.append(&mut pres);
            allow_pres_cls.append(&mut pres_cls);
        }
    }

    if denied {
        // Something explicitly said no.
        CreateResult::Deny
    } else if grant {
        // Something said yes
        CreateResult::Grant
    } else {
        let allowed_pres = if !constrain_pres.is_empty() {
            // bit_and
            &constrain_pres & &allow_pres
        } else {
            allow_pres
        };

        let mut allowed_pres_cls = if !constrain_pres_cls.is_empty() {
            // bit_and
            &constrain_pres_cls & &allow_pres_cls
        } else {
            allow_pres_cls
        };

        for protected_cls in PROTECTED_MOD_PRES_ENTRY_CLASSES.iter() {
            allowed_pres_cls.remove(protected_cls.as_str());
        }

        CreateResult::Allow {
            pres: allowed_pres,
            pres_cls: allowed_pres_cls,
        }
    }
}

fn create_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlCreateResolved],
    entry: &'a Entry<EntryInit, EntryNew>,
) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return IResult::Grant;
        }
        IdentType::Internal(InternalRole::Migration) => {
            // Checked in a separate function.
            return IResult::Ignore;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return IResult::Deny;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for create event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to create");
            return IResult::Deny;
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

    let create_classes: BTreeSet<&str> = match entry.get_ava_iter_iutf8(Attribute::Class) {
        Some(s) => s.collect(),
        None => {
            admin_error!("Class set failed to build - corrupted entry?");
            return IResult::Deny;
        }
    };

    //      Find the set of related acps for this entry.
    //
    //      For each "created" entry.
    //          If the created entry is 100% allowed by this acp
    //          IE: all attrs to be created AND classes match classes
    //              allow
    //          if no acp allows, fail operation.
    let allow = related_acp.iter().any(|accr| {
        // Assert that the receiver condition applies.
        match &accr.receiver_condition {
            AccessControlReceiverCondition::GroupChecked => {
                // The groups were already checked during filter resolution. Trust
                // that result, and continue.
            }
            AccessControlReceiverCondition::EntryManager => {
                // Currently, this is unsatisfiable for creates.
                return false;
            }
        };

        match &accr.target_condition {
            AccessControlTargetCondition::Scope(f_res) => {
                if !entry.entry_match_no_index(f_res) {
                    trace!(?entry, acs = %accr.acp.acp.name, "entry DOES NOT match acs");
                    // Does not match, fail this rule.
                    return false;
                }
            }
        };

        // -- Conditions pass -- now verify the attributes.

        let entry_name = entry.get_display_id();
        // It matches, so now we have to check attrs and classes.
        // Remember, we have to match ALL requested attrs
        // and classes to pass!
        let allowed_attrs: BTreeSet<&str> = accr.acp.attrs.iter().map(|s| s.as_str()).collect();
        let allowed_classes: BTreeSet<&str> = accr.acp.classes.iter().map(|s| s.as_str()).collect();

        if !create_attrs.is_subset(&allowed_attrs) {
            debug!(%entry_name, acs = ?accr.acp.acp.name, "entry create denied");
            debug!("create_attrs is not a subset of allowed");
            debug!("create: {:?} !⊆ allowed: {:?}", create_attrs, allowed_attrs);
            false
        } else if !create_classes.is_subset(&allowed_classes) {
            debug!(%entry_name, acs = ?accr.acp.acp.name, "entry create denied");
            debug!("create_classes is not a subset of allowed");
            debug!(
                "create: {:?} !⊆ allowed: {:?}",
                create_classes, allowed_classes
            );
            false
        } else {
            // All attribute conditions are now met.
            info!(%entry_name, acs = ?accr.acp.acp.name, "entry create allowed");
            debug!("create: {:?} ⊆ allowed: {:?}", create_attrs, allowed_attrs);
            debug!(
                "create: {:?} ⊆ allowed: {:?}",
                create_classes, allowed_classes
            );
            true
        }
    });

    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}

fn protected_filter_entry<'a>(ident: &Identity, entry: &Entry<EntryInit, EntryNew>) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::System) => {
            trace!("Internal operation, protected rules do not apply.");
            IResult::Ignore
        }
        IdentType::Synch(_) => {
            security_access!("sync agreements may not directly create entities");
            IResult::Deny
        }
        IdentType::Internal(InternalRole::Migration) | IdentType::User(_) => {
            if let Some(entry_uuid) = entry.get_uuid() {
                if entry_uuid <= UUID_ANONYMOUS {
                    security_access!("attempt to create a system builtin entry");
                    return IResult::Deny;
                }
            }

            // Now check things ...
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.is_disjoint(&PROTECTED_ENTRY_CLASSES) {
                    // It's different, go ahead
                    IResult::Ignore
                } else {
                    // Block the mod, something is present
                    security_access!("attempt to create with protected class type");
                    IResult::Deny
                }
            } else {
                // Nothing to check - this entry will fail to create anyway because it has
                // no classes
                IResult::Ignore
            }
        }
    }
}

fn migration_filter_entry<'a>(ident: &Identity, entry: &Entry<EntryInit, EntryNew>) -> IResult<'a> {
    match &ident.origin {
        IdentType::Internal(InternalRole::Migration) => {
            trace!(uuid = ?entry.get_display_id(), "Internal migration");

            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                let classes = classes.sub(&MIGRATION_IGNORE_CLASSES);
                if classes.is_subset(&MIGRATION_ENTRY_CLASSES) {
                    // Check what may be allowed
                    let (allow_attrs, allow_cls) = migration_entry_attrs(&classes);

                    if allow_attrs.is_empty() {
                        return IResult::Deny;
                    } else {
                        return IResult::Allow {
                            pres: allow_attrs,
                            pres_cls: allow_cls,
                        };
                    }
                }
            }
            IResult::Deny
        }
        _ => IResult::Ignore,
    }
}
