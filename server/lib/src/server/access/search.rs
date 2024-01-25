use crate::prelude::*;
use std::collections::BTreeSet;

use super::profiles::{
    AccessControlReceiverCondition, AccessControlSearchResolved, AccessControlTargetCondition,
};
use super::AccessResult;
use std::sync::Arc;

pub(super) enum SearchResult<'a> {
    Denied,
    Grant,
    Allow(BTreeSet<&'a str>),
}

pub(super) fn apply_search_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlSearchResolved],
    entry: &'a Arc<EntrySealedCommitted>,
) -> SearchResult<'a> {
    // This could be considered "slow" due to allocs each iter with the entry. We
    // could move these out of the loop and reuse, but there are likely risks to
    // that.
    let mut denied = false;
    let mut grant = false;
    let mut constrain = BTreeSet::default();
    let mut allow = BTreeSet::default();

    // The access control profile
    match search_filter_entry(ident, related_acp, entry) {
        AccessResult::Denied => denied = true,
        AccessResult::Grant => grant = true,
        AccessResult::Ignore => {}
        AccessResult::Constrain(mut set) => constrain.append(&mut set),
        AccessResult::Allow(mut set) => allow.append(&mut set),
    };

    match search_oauth2_filter_entry(ident, entry) {
        AccessResult::Denied => denied = true,
        AccessResult::Grant => grant = true,
        AccessResult::Ignore => {}
        AccessResult::Constrain(mut set) => constrain.append(&mut set),
        AccessResult::Allow(mut set) => allow.append(&mut set),
    };

    match search_sync_account_filter_entry(ident, entry) {
        AccessResult::Denied => denied = true,
        AccessResult::Grant => grant = true,
        AccessResult::Ignore => {}
        AccessResult::Constrain(mut set) => constrain.append(&mut set),
        AccessResult::Allow(mut set) => allow.append(&mut set),
    };

    // We'll add more modules later.

    // Now finalise the decision.

    if denied {
        SearchResult::Denied
    } else if grant {
        SearchResult::Grant
    } else {
        let allowed_attrs = if !constrain.is_empty() {
            // bit_and
            &constrain & &allow
        } else {
            allow
        };
        SearchResult::Allow(allowed_attrs)
    }
}

fn search_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlSearchResolved],
    entry: &'a Arc<EntrySealedCommitted>,
) -> AccessResult<'a> {
    // If this is an internal search, return our working set.
    match &ident.origin {
        IdentType::Internal => {
            trace!(uuid = ?entry.get_display_id(), "Internal operation, bypassing access check");
            // No need to check ACS
            return AccessResult::Grant;
        }
        IdentType::Synch(_) => {
            security_critical!(uuid = ?entry.get_display_id(), "Blocking sync check");
            return AccessResult::Denied;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for search (filter) event");

    match ident.access_scope() {
        AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to search");
            return AccessResult::Denied;
        }
        AccessScope::ReadOnly | AccessScope::ReadWrite => {
            // As you were
        }
    };

    // needed for checking entry manager conditions.
    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    let allowed_attrs: BTreeSet<&str> = related_acp
        .iter()
        .filter_map(|acs| {
            // Assert that the receiver condition applies.
            match &acs.receiver_condition {
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
                    if let Some(entry_manager_uuids) = entry.get_ava_refer(Attribute::EntryManagedBy) {
                        let group_check = ident_memberof
                            // Have at least one group allowed.
                            .map(|imo| imo.intersection(entry_manager_uuids).next().is_some())
                            .unwrap_or_default();

                        let user_check = ident_uuid
                            .map(|u| entry_manager_uuids.contains(&u))
                            .unwrap_or_default();

                        if !(group_check || user_check) {
                            // Not the entry manager
                            return None
                        }
                    } else {
                        // Can not satsify.
                        return None
                    }
                }
            };

            match &acs.target_condition {
                AccessControlTargetCondition::Scope(f_res) => {
                    if !entry.entry_match_no_index(f_res) {
                        // should this be `security_access`?
                        security_debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, "entry DOES NOT match acs");
                        return None
                    }
                }
            };

            // -- Conditions pass -- release the attributes.

            security_debug!(entry = ?entry.get_display_id(), acs = %acs.acp.acp.name, "acs applied to entry");
            // add search_attrs to allowed.
            Some(acs.acp.attrs.iter().map(|s| s.as_str()))
        })
        .flatten()
        .collect();

    AccessResult::Allow(allowed_attrs)
}

fn search_oauth2_filter_entry<'a>(
    ident: &Identity,
    entry: &'a Arc<EntrySealedCommitted>,
) -> AccessResult<'a> {
    match &ident.origin {
        IdentType::Internal | IdentType::Synch(_) => AccessResult::Ignore,
        IdentType::User(iuser) => {
            let contains_o2_rs = entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|set| {
                    trace!(?set);
                    set.contains(&EntryClass::OAuth2ResourceServer.to_string())
                })
                .unwrap_or(false);

            let contains_o2_scope_member = entry
                .get_ava_as_oauthscopemaps(Attribute::OAuth2RsScopeMap)
                .and_then(|maps| ident.get_memberof().map(|mo| (maps, mo)))
                .map(|(maps, mo)| maps.keys().any(|k| mo.contains(k)))
                .unwrap_or(false);

            if contains_o2_rs && contains_o2_scope_member {
                security_access!(entry = ?entry.get_uuid(), ident = ?iuser.entry.get_uuid2rdn(), "ident is a memberof a group granted an oauth2 scope by this entry");

                return AccessResult::Allow(btreeset!(
                    Attribute::Class.as_ref(),
                    Attribute::DisplayName.as_ref(),
                    Attribute::Uuid.as_ref(),
                    Attribute::Name.as_ref(),
                    Attribute::OAuth2RsOrigin.as_ref(),
                    Attribute::OAuth2RsOriginLanding.as_ref(),
                    Attribute::Image.as_ref()
                ));
            }
            AccessResult::Ignore
        }
    }
}

fn search_sync_account_filter_entry<'a>(
    ident: &Identity,
    entry: &'a Arc<EntrySealedCommitted>,
) -> AccessResult<'a> {
    match &ident.origin {
        IdentType::Internal | IdentType::Synch(_) => AccessResult::Ignore,
        IdentType::User(iuser) => {
            // Is the user a synced object?
            let is_user_sync_account = iuser
                .entry
                .get_ava_as_iutf8(Attribute::Class)
                .map(|set| {
                    trace!(?set);
                    set.contains(&EntryClass::SyncObject.to_string())
                        && set.contains(EntryClass::Account.into())
                })
                .unwrap_or(false);

            if is_user_sync_account {
                let is_target_sync_account = entry
                    .get_ava_as_iutf8(Attribute::Class)
                    .map(|set| {
                        trace!(?set);
                        set.contains(&EntryClass::SyncAccount.to_string())
                    })
                    .unwrap_or(false);

                if is_target_sync_account {
                    // Okay, now we need to check if the uuids line up.
                    let sync_uuid = entry.get_uuid();
                    let sync_source_match = iuser
                        .entry
                        .get_ava_single_refer(Attribute::SyncParentUuid)
                        .map(|sync_parent_uuid| sync_parent_uuid == sync_uuid)
                        .unwrap_or(false);

                    if sync_source_match {
                        // We finally got here!
                        security_access!(entry = ?entry.get_uuid(), ident = ?iuser.entry.get_uuid2rdn(), "ident is a synchronsied account from this sync account");

                        return AccessResult::Allow(btreeset!(
                            Attribute::Class.as_ref(),
                            Attribute::Uuid.as_ref(),
                            Attribute::SyncCredentialPortal.as_ref()
                        ));
                    }
                }
            }
            // Fall through
            AccessResult::Ignore
        }
    }
}
