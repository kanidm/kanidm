//! Access Control Profiles
//!
//! This is a pretty important and security sensitive part of the code - it's
//! responsible for making sure that who is allowed to do what is enforced, as
//! well as who is *not* allowed to do what.
//!
//! A detailed design can be found in access-profiles-and-security.
//!
//! This component of the server really has a few parts
//! - the ability to parse access profile structures into real ACP structs
//! - the ability to apply sets of ACP's to entries for coarse actions (IE
//!   search.
//! - the ability to turn an entry into a partial-entry for results send
//!   requirements (also search).

use std::cell::Cell;
use std::collections::BTreeSet;
use std::ops::DerefMut;
use std::sync::Arc;

use concread::arcache::{ARCache, ARCacheBuilder, ARCacheReadTxn};
use concread::cowcell::*;
use kanidm_proto::v1::OperationError;
use tracing::trace;
use uuid::Uuid;

use crate::entry::{Entry, EntryCommitted, EntryInit, EntryNew, EntryReduced};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
use crate::filter::{Filter, FilterValid, FilterValidResolved};
use crate::modify::Modify;
use crate::prelude::*;

use self::profiles::{
    AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlSearch,
};

use self::create::{apply_create_access, CreateResult};
use self::delete::{apply_delete_access, DeleteResult};
use self::modify::{apply_modify_access, ModifyResult};
use self::search::{apply_search_access, SearchResult};

const ACP_RESOLVE_FILTER_CACHE_MAX: usize = 2048;
const ACP_RESOLVE_FILTER_CACHE_LOCAL: usize = 16;

mod create;
mod delete;
mod modify;
pub mod profiles;
mod search;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Grant,
    Denied,
    Allow(BTreeSet<AttrString>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEffectivePermission {
    // I don't think we need this? The ident is implied by the requestor.
    // ident: Uuid,
    pub target: Uuid,
    pub delete: bool,
    pub search: Access,
    pub modify_pres: Access,
    pub modify_rem: Access,
    pub modify_class: Access,
}

pub enum AccessResult<'a> {
    // Deny this operation unconditionally.
    Denied,
    // Unbounded allow, provided no denied exists.
    Grant,
    // This module makes no decisions about this entry.
    Ignore,
    // Limit the allowed attr set to this.
    Constrain(BTreeSet<&'a str>),
    // Allow these attributes within constraints.
    Allow(BTreeSet<&'a str>),
}

// =========================================================================
// ACP transactions and management for server bits.
// =========================================================================

#[derive(Clone)]
struct AccessControlsInner {
    acps_search: Vec<AccessControlSearch>,
    acps_create: Vec<AccessControlCreate>,
    acps_modify: Vec<AccessControlModify>,
    acps_delete: Vec<AccessControlDelete>,
    // Oauth2
    // Sync prov
}

pub struct AccessControls {
    inner: CowCell<AccessControlsInner>,
    // acp_related_search_cache: ARCache<Uuid, Vec<Uuid>>,
    acp_resolve_filter_cache:
        ARCache<(IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>>,
}

pub trait AccessControlsTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch>;
    fn get_create(&self) -> &Vec<AccessControlCreate>;
    fn get_modify(&self) -> &Vec<AccessControlModify>;
    fn get_delete(&self) -> &Vec<AccessControlDelete>;

    #[allow(clippy::mut_from_ref)]
    fn get_acp_resolve_filter_cache(
        &self,
    ) -> &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>;

    #[instrument(level = "debug", name = "access::search_related_acp", skip_all)]
    fn search_related_acp<'b>(
        &'b self,
        ident: &Identity,
    ) -> Vec<(&'b AccessControlSearch, Filter<FilterValidResolved>)> {
        let search_state = self.get_search();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        // ⚠️  WARNING ⚠️  -- Why is this cache commented out?
        //
        // The reason for this is that to determine what acps relate, we need to be
        // aware of session claims - since these can change session to session, we
        // would need the cache to be structured to handle this. It's much better
        // in a search to just lean on the filter resolve cache because of this
        // dynamic behaviour.
        //
        // It may be possible to do per-operation caching when we know that we will
        // perform the reduce step, but it may not be worth it. It's probably better
        // to make entry_match_no_index faster.

        /*
        if let Some(acs_uuids) = acp_related_search_cache.get(rec_entry.get_uuid()) {
            lperf_trace_segment!( "access::search_related_acp<cached>", || {
                // If we have a cache, we should look here first for all the uuids that match

                // could this be a better algo?
                search_state
                    .iter()
                    .filter(|acs| acs_uuids.binary_search(&acs.acp.uuid).is_ok())
                    .collect()
            })
        } else {
        */
        // else, we calculate this, and then stash/cache the uuids.
        let related_acp: Vec<(&AccessControlSearch, Filter<FilterValidResolved>)> = search_state
            .iter()
            .filter_map(|acs| {
                // Now resolve the receiver filter
                // Okay, so in filter resolution, the primary error case
                // is that we have a non-user in the event. We have already
                // checked for this above BUT we should still check here
                // properly just in case.
                //
                // In this case, we assume that if the event is internal
                // that the receiver can NOT match because it has no selfuuid
                // and can as a result, never return true. This leads to this
                // acp not being considered in that case ... which should never
                // happen because we already bypassed internal ops above!
                //
                // A possible solution is to change the filter resolve function
                // such that it takes an entry, rather than an event, but that
                // would create issues in search.
                if let Some(receiver) = acs.acp.receiver {
                    if ident.is_memberof(receiver) {
                        // Now, for each of the acp's that apply to our receiver, resolve their
                        // related target filters.
                        acs.acp
                            .targetscope
                            .resolve(ident, None, Some(acp_resolve_filter_cache))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "A internal filter/event was passed for resolution!?!?"
                                );
                                e
                            })
                            .ok()
                            .map(|f_res| (acs, f_res))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        related_acp
        // }
    }

    // Contains all the way to eval acps to entries
    #[instrument(level = "debug", name = "access::search_filter_entries", skip_all)]
    fn search_filter_entries(
        &self,
        se: &SearchEvent,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        // Prepare some shared resources.

        // Get the set of attributes requested by this se filter. This is what we are
        // going to access check.
        let requested_attrs: BTreeSet<&str> = se.filter_orig.get_attr_set();

        // First get the set of acps that apply to this receiver
        let related_acp: Vec<(&AccessControlSearch, _)> = self.search_related_acp(&se.ident);

        // For each entry.
        let allowed_entries: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                match apply_search_access(&se.ident, related_acp.as_slice(), e) {
                    SearchResult::Denied => false,
                    SearchResult::Grant => true,
                    SearchResult::Allow(allowed_attrs) => {
                        // The allow set constrained.
                        security_access!(
                            requested = ?requested_attrs,
                            allowed = ?allowed_attrs,
                            "attributes",
                        );

                        let decision = requested_attrs.is_subset(&allowed_attrs);
                        security_access!(?decision, "search attr decision");
                        decision
                    }
                }
            })
            .collect();

        if allowed_entries.is_empty() {
            security_access!("denied ❌");
        } else {
            security_access!("allowed {} entries ✅", allowed_entries.len());
        }

        Ok(allowed_entries)
    }

    #[instrument(
        level = "debug",
        name = "access::search_filter_entry_attributes",
        skip_all
    )]
    fn search_filter_entry_attributes(
        &self,
        se: &SearchEvent,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        // Build a reference set from the req_attrs. This is what we test against
        // to see if the attribute is something we currently want.
        let requested_attrs: Option<BTreeSet<_>> = se
            .attrs
            .as_ref()
            .map(|vs| vs.iter().map(|s| s.as_str()).collect());

        // Get the relevant acps for this receiver.
        let related_acp: Vec<(&AccessControlSearch, _)> = self.search_related_acp(&se.ident);
        let related_acp: Vec<(&AccessControlSearch, _)> = if let Some(r_attrs) = se.attrs.as_ref() {
            // If the acp doesn't overlap with our requested attrs, there is no point in
            // testing it!
            related_acp
                .into_iter()
                .filter(|(acs, _)| !acs.attrs.is_disjoint(r_attrs))
                .collect()
        } else {
            related_acp
        };

        // For each entry.
        let allowed_entries: Vec<_> = entries
            .into_iter()
            .filter_map(|e| {
                match apply_search_access(&se.ident, related_acp.as_slice(), &e) {
                    SearchResult::Denied => None,
                    SearchResult::Grant => {
                        if cfg!(test) {
                            // We only allow this during tests.
                            // No properly written access module should allow
                            // unbounded attribute read!
                            Some(unsafe { e.as_ref().clone().into_reduced() })
                        } else {
                            None
                        }
                    }
                    SearchResult::Allow(allowed_attrs) => {
                        // The allow set constrained.
                        security_access!(
                            requested = ?requested_attrs,
                            allowed = ?allowed_attrs,
                            "attributes",
                        );
                        // The allow set constrained.
                        security_access!(
                            requested = ?requested_attrs,
                            allowed = ?allowed_attrs,
                            "attributes",
                        );

                        // Reduce requested by allowed.
                        let reduced_attrs = if let Some(requested) = requested_attrs.as_ref() {
                            requested & &allowed_attrs
                        } else {
                            allowed_attrs
                        };

                        if reduced_attrs.is_empty() {
                            None
                        } else {
                            Some(e.reduce_attributes(&reduced_attrs))
                        }
                    }
                }

                // End filter
            })
            .collect();

        if allowed_entries.is_empty() {
            security_access!("reduced to empty set on all entries ❌");
        } else {
            security_access!(
                "attribute set reduced on {} entries ✅",
                allowed_entries.len()
            );
        }

        Ok(allowed_entries)
    }

    #[instrument(level = "debug", name = "access::modify_related_acp", skip_all)]
    fn modify_related_acp<'b>(
        &'b self,
        ident: &Identity,
    ) -> Vec<(&'b AccessControlModify, Filter<FilterValidResolved>)> {
        // Some useful references we'll use for the remainder of the operation
        let modify_state = self.get_modify();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<(&AccessControlModify, _)> = modify_state
            .iter()
            .filter_map(|acs| {
                if let Some(receiver) = acs.acp.receiver {
                    if ident.is_memberof(receiver) {
                        acs.acp
                            .targetscope
                            .resolve(ident, None, Some(acp_resolve_filter_cache))
                            .map_err(|e| {
                                admin_error!(
                                    "A internal filter/event was passed for resolution!?!? {:?}",
                                    e
                                );
                                e
                            })
                            .ok()
                            .map(|f_res| (acs, f_res))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        related_acp
    }

    #[instrument(level = "debug", name = "access::modify_allow_operation", skip_all)]
    fn modify_allow_operation(
        &self,
        me: &ModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Pre-check if the no-no purge class is present
        let disallow = me
            .modlist
            .iter()
            .any(|m| matches!(m, Modify::Purged(a) if a == "class"));

        if disallow {
            security_access!("Disallowing purge class in modification");
            return Ok(false);
        }

        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<(&AccessControlModify, _)> = self.modify_related_acp(&me.ident);

        // build two sets of "requested pres" and "requested rem"
        let requested_pres: BTreeSet<&str> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Present(a, _) => Some(a.as_str()),
                _ => None,
            })
            .collect();

        let requested_rem: BTreeSet<&str> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Removed(a, _) => Some(a.as_str()),
                Modify::Purged(a) => Some(a.as_str()),
                _ => None,
            })
            .collect();

        // Build the set of classes that we to work on, only in terms of "addition". To remove
        // I think we have no limit, but ... william of the future may find a problem with this
        // policy.
        let requested_classes: BTreeSet<&str> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Present(a, v) => {
                    if a.as_str() == "class" {
                        // Here we have an option<&str> which could mean there is a risk of
                        // a malicious entity attempting to trick us by masking class mods
                        // in non-iutf8 types. However, the server first won't respect their
                        // existence, and second, we would have failed the mod at schema checking
                        // earlier in the process as these were not correctly type. As a result
                        // we can trust these to be correct here and not to be "None".
                        v.to_str()
                    } else {
                        None
                    }
                }
                Modify::Removed(a, v) => {
                    if a.as_str() == "class" {
                        v.to_str()
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();

        security_access!(?requested_pres, "Requested present set");
        security_access!(?requested_rem, "Requested remove set");
        security_access!(?requested_classes, "Requested class set");

        let r = entries.iter().all(|e| {
            match apply_modify_access(&me.ident, related_acp.as_slice(), e) {
                ModifyResult::Denied => false,
                ModifyResult::Grant => true,
                ModifyResult::Allow { pres, rem, cls } => {
                    if !requested_pres.is_subset(&pres) {
                        security_access!("requested_pres is not a subset of allowed");
                        security_access!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        false
                    } else if !requested_rem.is_subset(&rem) {
                        security_access!("requested_rem is not a subset of allowed");
                        security_access!(
                            "requested_rem: {:?} !⊆ allowed: {:?}",
                            requested_rem,
                            rem
                        );
                        false
                    } else if !requested_classes.is_subset(&cls) {
                        security_access!("requested_classes is not a subset of allowed");
                        security_access!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_classes,
                            cls
                        );
                        false
                    } else {
                        security_access!("passed pres, rem, classes check.");
                        true
                    } // if acc == false
                }
            }
        });

        if r {
            security_access!("allowed ✅");
        } else {
            security_access!("denied ❌");
        }
        Ok(r)
    }

    #[instrument(
        level = "debug",
        name = "access::batch_modify_allow_operation",
        skip_all
    )]
    fn batch_modify_allow_operation(
        &self,
        me: &BatchModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<(&AccessControlModify, _)> = self.modify_related_acp(&me.ident);

        let r = entries.iter().all(|e| {
            // Due to how batch mod works, we have to check the modlist *per entry* rather
            // than as a whole.

            let modlist = if let Some(mlist) = me.modset.get(&e.get_uuid()) {
                mlist
            } else {
                security_access!(
                    "modlist not present for {}, failing operation.",
                    e.get_uuid()
                );
                return false;
            };

            let disallow = modlist
                .iter()
                .any(|m| matches!(m, Modify::Purged(a) if a == "class"));

            if disallow {
                security_access!("Disallowing purge class in modification");
                return false;
            }

            // build two sets of "requested pres" and "requested rem"
            let requested_pres: BTreeSet<&str> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Present(a, _) => Some(a.as_str()),
                    _ => None,
                })
                .collect();

            let requested_rem: BTreeSet<&str> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Removed(a, _) => Some(a.as_str()),
                    Modify::Purged(a) => Some(a.as_str()),
                    _ => None,
                })
                .collect();

            // Build the set of classes that we to work on, only in terms of "addition". To remove
            // I think we have no limit, but ... william of the future may find a problem with this
            // policy.
            let requested_classes: BTreeSet<&str> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Present(a, v) => {
                        if a.as_str() == "class" {
                            // Here we have an option<&str> which could mean there is a risk of
                            // a malicious entity attempting to trick us by masking class mods
                            // in non-iutf8 types. However, the server first won't respect their
                            // existence, and second, we would have failed the mod at schema checking
                            // earlier in the process as these were not correctly type. As a result
                            // we can trust these to be correct here and not to be "None".
                            v.to_str()
                        } else {
                            None
                        }
                    }
                    Modify::Removed(a, v) => {
                        if a.as_str() == "class" {
                            v.to_str()
                        } else {
                            None
                        }
                    }
                    _ => None,
                })
                .collect();

            security_access!(?requested_pres, "Requested present set");
            security_access!(?requested_rem, "Requested remove set");
            security_access!(?requested_classes, "Requested class set");

            match apply_modify_access(&me.ident, related_acp.as_slice(), e) {
                ModifyResult::Denied => false,
                ModifyResult::Grant => true,
                ModifyResult::Allow { pres, rem, cls } => {
                    if !requested_pres.is_subset(&pres) {
                        security_access!("requested_pres is not a subset of allowed");
                        security_access!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        false
                    } else if !requested_rem.is_subset(&rem) {
                        security_access!("requested_rem is not a subset of allowed");
                        security_access!(
                            "requested_rem: {:?} !⊆ allowed: {:?}",
                            requested_rem,
                            rem
                        );
                        false
                    } else if !requested_classes.is_subset(&cls) {
                        security_access!("requested_classes is not a subset of allowed");
                        security_access!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_classes,
                            cls
                        );
                        false
                    } else {
                        security_access!("passed pres, rem, classes check.");
                        true
                    } // if acc == false
                }
            }
        });

        if r {
            security_access!("allowed ✅");
        } else {
            security_access!("denied ❌");
        }
        Ok(r)
    }

    #[instrument(level = "debug", name = "access::create_allow_operation", skip_all)]
    fn create_allow_operation(
        &self,
        ce: &CreateEvent,
        entries: &[Entry<EntryInit, EntryNew>],
    ) -> Result<bool, OperationError> {
        // Some useful references we'll use for the remainder of the operation
        let create_state = self.get_create();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        // Find the acps that relate to the caller.
        let related_acp: Vec<(&AccessControlCreate, _)> = create_state
            .iter()
            .filter_map(|acs| {
                if let Some(receiver) = acs.acp.receiver {
                    if ce.ident.is_memberof(receiver) {
                        acs.acp
                            .targetscope
                            .resolve(&ce.ident, None, Some(acp_resolve_filter_cache))
                            .map_err(|e| {
                                admin_error!(
                                    "A internal filter/event was passed for resolution!?!? {:?}",
                                    e
                                );
                                e
                            })
                            .ok()
                            .map(|f_res| (acs, f_res))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // For each entry
        let r = entries.iter().all(|e| {
            match apply_create_access(&ce.ident, related_acp.as_slice(), e) {
                CreateResult::Denied => false,
                CreateResult::Grant => true,
            }
        });

        if r {
            security_access!("allowed ✅");
        } else {
            security_access!("denied ❌");
        }

        Ok(r)
    }

    #[instrument(level = "debug", name = "access::delete_related_acp", skip_all)]
    fn delete_related_acp<'b>(
        &'b self,
        ident: &Identity,
    ) -> Vec<(&'b AccessControlDelete, Filter<FilterValidResolved>)> {
        // Some useful references we'll use for the remainder of the operation
        let delete_state = self.get_delete();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let related_acp: Vec<(&AccessControlDelete, _)> = delete_state
            .iter()
            .filter_map(|acs| {
                if let Some(receiver) = acs.acp.receiver {
                    if ident.is_memberof(receiver) {
                        acs.acp
                            .targetscope
                            .resolve(ident, None, Some(acp_resolve_filter_cache))
                            .map_err(|e| {
                                admin_error!(
                                    "A internal filter/event was passed for resolution!?!? {:?}",
                                    e
                                );
                                e
                            })
                            .ok()
                            .map(|f_res| (acs, f_res))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        related_acp
    }

    #[instrument(level = "debug", name = "access::delete_allow_operation", skip_all)]
    fn delete_allow_operation(
        &self,
        de: &DeleteEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Find the acps that relate to the caller.
        let related_acp = self.delete_related_acp(&de.ident);

        // For each entry
        let r = entries.iter().all(|e| {
            match apply_delete_access(&de.ident, related_acp.as_slice(), e) {
                DeleteResult::Denied => false,
                DeleteResult::Grant => true,
            }
        });
        if r {
            security_access!("allowed ✅");
        } else {
            security_access!("denied ❌");
        }
        Ok(r)
    }

    #[instrument(level = "debug", name = "access::effective_permission_check", skip_all)]
    fn effective_permission_check(
        &self,
        ident: &Identity,
        attrs: Option<BTreeSet<AttrString>>,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<Vec<AccessEffectivePermission>, OperationError> {
        // I think we need a structure like " CheckResult, which is in the order of the
        // entries, but also stashes the uuid. Then it has search, mod, create, delete,
        // as separate attrs to describe what is capable.

        // Does create make sense here? I don't think it does. Create requires you to
        // have an entry template. I think james was right about the create being
        // a template copy op ...

        match &ident.origin {
            IdentType::Internal => {
                // In production we can't risk leaking data here, so we return
                // empty sets.
                security_critical!("IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                // No need to check ACS
                return Err(OperationError::InvalidState);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(_) => {}
        };

        trace!(ident = %ident, "Effective permission check");
        // I think we separate this to multiple checks ...?

        // == search ==
        // Get the relevant acps for this receiver.
        let search_related_acp: Vec<(&AccessControlSearch, _)> = self.search_related_acp(ident);
        let search_related_acp: Vec<(&AccessControlSearch, _)> =
            if let Some(r_attrs) = attrs.as_ref() {
                search_related_acp
                    .into_iter()
                    .filter(|(acs, _)| !acs.attrs.is_disjoint(r_attrs))
                    .collect()
            } else {
                search_related_acp
            };

        // == modify ==

        let modify_related_acp = self.modify_related_acp(ident);
        let delete_related_acp = self.delete_related_acp(ident);

        let effective_permissions: Vec<_> = entries
            .iter()
            .map(|e| {
                // == search ==
                let search_effective =
                    match apply_search_access(ident, search_related_acp.as_slice(), e) {
                        SearchResult::Denied => Access::Denied,
                        SearchResult::Grant => Access::Grant,
                        SearchResult::Allow(allowed_attrs) => {
                            // Bound by requested attrs?
                            Access::Allow(allowed_attrs.into_iter().map(|s| s.into()).collect())
                        }
                    };

                // == modify ==

                let (modify_pres, modify_rem, modify_class) =
                    match apply_modify_access(ident, modify_related_acp.as_slice(), e) {
                        ModifyResult::Denied => (Access::Denied, Access::Denied, Access::Denied),
                        ModifyResult::Grant => (Access::Grant, Access::Grant, Access::Grant),
                        ModifyResult::Allow { pres, rem, cls } => (
                            Access::Allow(pres.into_iter().map(|s| s.into()).collect()),
                            Access::Allow(rem.into_iter().map(|s| s.into()).collect()),
                            Access::Allow(cls.into_iter().map(|s| s.into()).collect()),
                        ),
                    };

                // == delete ==
                let delete = delete_related_acp.iter().any(|(acd, f_res)| {
                    if e.entry_match_no_index(f_res) {
                        security_access!(
                            entry_uuid = ?e.get_uuid(),
                            acs = %acd.acp.name,
                            "entry matches acd"
                        );
                        true
                    } else {
                        false
                    }
                });

                AccessEffectivePermission {
                    target: e.get_uuid(),
                    delete,
                    search: search_effective,
                    modify_pres,
                    modify_rem,
                    modify_class,
                }
            })
            .collect();

        effective_permissions.iter().for_each(|ep| {
            trace!(?ep);
        });

        Ok(effective_permissions)
    }
}

pub struct AccessControlsWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, AccessControlsInner>,
    acp_resolve_filter_cache: Cell<
        ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>,
    >,
}

impl<'a> AccessControlsWriteTransaction<'a> {
    // We have a method to update each set, so that if an error
    // occurs we KNOW it's an error, rather than using errors as
    // part of the logic (IE try-parse-fail method).
    pub fn update_search(
        &mut self,
        mut acps: Vec<AccessControlSearch>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_search);
        Ok(())
    }

    pub fn update_create(
        &mut self,
        mut acps: Vec<AccessControlCreate>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_create);
        Ok(())
    }

    pub fn update_modify(
        &mut self,
        mut acps: Vec<AccessControlModify>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_modify);
        Ok(())
    }

    pub fn update_delete(
        &mut self,
        mut acps: Vec<AccessControlDelete>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_delete);
        Ok(())
    }

    pub fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();

        Ok(())
    }
}

impl<'a> AccessControlsTransaction<'a> for AccessControlsWriteTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch> {
        &self.inner.acps_search
    }

    fn get_create(&self) -> &Vec<AccessControlCreate> {
        &self.inner.acps_create
    }

    fn get_modify(&self) -> &Vec<AccessControlModify> {
        &self.inner.acps_modify
    }

    fn get_delete(&self) -> &Vec<AccessControlDelete> {
        &self.inner.acps_delete
    }

    fn get_acp_resolve_filter_cache(
        &self,
    ) -> &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>
    {
        unsafe {
            let mptr = self.acp_resolve_filter_cache.as_ptr();
            &mut (*mptr)
                as &mut ARCacheReadTxn<
                    'a,
                    (IdentityId, Filter<FilterValid>),
                    Filter<FilterValidResolved>,
                    (),
                >
        }
    }
}

// =========================================================================
// ACP operations (Should this actually be on the ACP's themself?
// =========================================================================

pub struct AccessControlsReadTransaction<'a> {
    inner: CowCellReadTxn<AccessControlsInner>,
    // acp_related_search_cache: Cell<ARCacheReadTxn<'a, Uuid, Vec<Uuid>>>,
    acp_resolve_filter_cache: Cell<
        ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>,
    >,
}

unsafe impl<'a> Sync for AccessControlsReadTransaction<'a> {}

unsafe impl<'a> Send for AccessControlsReadTransaction<'a> {}

impl<'a> AccessControlsTransaction<'a> for AccessControlsReadTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch> {
        &self.inner.acps_search
    }

    fn get_create(&self) -> &Vec<AccessControlCreate> {
        &self.inner.acps_create
    }

    fn get_modify(&self) -> &Vec<AccessControlModify> {
        &self.inner.acps_modify
    }

    fn get_delete(&self) -> &Vec<AccessControlDelete> {
        &self.inner.acps_delete
    }

    fn get_acp_resolve_filter_cache(
        &self,
    ) -> &mut ARCacheReadTxn<'a, (IdentityId, Filter<FilterValid>), Filter<FilterValidResolved>, ()>
    {
        unsafe {
            let mptr = self.acp_resolve_filter_cache.as_ptr();
            &mut (*mptr)
                as &mut ARCacheReadTxn<
                    'a,
                    (IdentityId, Filter<FilterValid>),
                    Filter<FilterValidResolved>,
                    (),
                >
        }
    }
}

// =========================================================================
// ACP transaction operations
// =========================================================================

impl Default for AccessControls {
    #![allow(clippy::expect_used)]
    fn default() -> Self {
        AccessControls {
            inner: CowCell::new(AccessControlsInner {
                acps_search: Vec::new(),
                acps_create: Vec::new(),
                acps_modify: Vec::new(),
                acps_delete: Vec::new(),
            }),
            // Allow the expect, if this fails it represents a programming/development
            // failure.
            acp_resolve_filter_cache: ARCacheBuilder::new()
                .set_size(ACP_RESOLVE_FILTER_CACHE_MAX, ACP_RESOLVE_FILTER_CACHE_LOCAL)
                .set_reader_quiesce(true)
                .build()
                .expect("Failed to construct acp_resolve_filter_cache"),
        }
    }
}

impl AccessControls {
    pub fn try_quiesce(&self) {
        self.acp_resolve_filter_cache.try_quiesce();
    }

    pub fn read(&self) -> AccessControlsReadTransaction {
        AccessControlsReadTransaction {
            inner: self.inner.read(),
            // acp_related_search_cache: Cell::new(self.acp_related_search_cache.read()),
            acp_resolve_filter_cache: Cell::new(self.acp_resolve_filter_cache.read()),
        }
    }

    pub fn write(&self) -> AccessControlsWriteTransaction {
        AccessControlsWriteTransaction {
            inner: self.inner.write(),
            // acp_related_search_cache_wr: self.acp_related_search_cache.write(),
            // acp_related_search_cache: Cell::new(self.acp_related_search_cache.read()),
            acp_resolve_filter_cache: Cell::new(self.acp_resolve_filter_cache.read()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use uuid::uuid;

    use super::{
        profiles::{
            AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlProfile,
            AccessControlSearch,
        },
        Access, AccessControls, AccessControlsTransaction, AccessEffectivePermission,
    };
    use crate::prelude::*;

    const UUID_TEST_ACCOUNT_1: Uuid = uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
    const UUID_TEST_ACCOUNT_2: Uuid = uuid::uuid!("cec0852a-abdf-4ea6-9dae-d3157cb33d3a");
    const UUID_TEST_GROUP_1: Uuid = uuid::uuid!("81ec1640-3637-4a2f-8a52-874fa3c3c92f");
    const UUID_TEST_GROUP_2: Uuid = uuid::uuid!("acae81d6-5ea7-4bd8-8f7f-fcec4c0dd647");

    lazy_static! {
        pub static ref E_TEST_ACCOUNT_1: Arc<EntrySealedCommitted> = Arc::new(unsafe {
            entry_init!(
                ("class", Value::new_class("object")),
                ("name", Value::new_iname("test_account_1")),
                ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1)),
                ("memberof", Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed()
        });
        pub static ref E_TEST_ACCOUNT_2: Arc<EntrySealedCommitted> = Arc::new(unsafe {
            entry_init!(
                ("class", Value::new_class("object")),
                ("name", Value::new_iname("test_account_1")),
                ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_2)),
                ("memberof", Value::Refer(UUID_TEST_GROUP_2))
            )
            .into_sealed_committed()
        });
    }

    macro_rules! acp_from_entry_err {
        (
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str($e);
            let ev1 = unsafe { e1.into_sealed_committed() };

            let r1 = <$type>::try_from($qs, &ev1);
            assert!(r1.is_err());
        }};
    }

    macro_rules! acp_from_entry_ok {
        (
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = unsafe { $e.into_sealed_committed() };

            let r1 = <$type>::try_from($qs, &ev1);
            assert!(r1.is_ok());
            r1.unwrap()
        }};
    }

    #[qs_test]
    async fn test_access_acp_parser(qs: &QueryServer) {
        // Test parsing entries to acp. There so no point testing schema violations
        // because the schema system is well tested an robust. Instead we target
        // entry misconfigurations, such as missing classes required.

        // Generally, we are testing the *positive* cases here, because schema
        // really protects us *a lot* here, but it's nice to have defence and
        // layers of validation.

        let mut qs_write = qs.write(duration_from_epoch_now()).await;

        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                    }
                }"#,
            AccessControlProfile
        );

        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
                    }
                }"#,
            AccessControlProfile
        );

        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [""]
                    }
                }"#,
            AccessControlProfile
        );

        // "\"Self\""
        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlProfile
        );
    }

    #[qs_test]
    async fn test_access_acp_delete_parser(qs: &QueryServer) {
        let mut qs_write = qs.write(duration_from_epoch_now()).await;

        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [
                            "{\"eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
            AccessControlDelete
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("class", Value::new_class("access_control_delete")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlDelete
        );
    }

    #[qs_test]
    async fn test_access_acp_search_parser(qs: &QueryServer) {
        // Test that parsing search access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await;

        // Missing class acp
        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_search"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [
                            "{\"eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_search_attr": ["name", "class"]
                    }
                }"#,
            AccessControlSearch
        );

        // Missing class acs
        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [
                            "{\"eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_search_attr": ["name", "class"]
                    }
                }"#,
            AccessControlSearch
        );

        // Missing attr acp_search_attr
        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile", "access_control_search"],
                        "name": ["acp_invalid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [
                            "{\"eq\":[\"name\",\"a\"]}"
                        ]
                    }
                }"#,
            AccessControlSearch
        );

        // All good!
        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("class", Value::new_class("access_control_search")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                ("acp_search_attr", Value::new_iutf8("name")),
                ("acp_search_attr", Value::new_iutf8("class"))
            ),
            AccessControlSearch
        );
    }

    #[qs_test]
    async fn test_access_acp_modify_parser(qs: &QueryServer) {
        // Test that parsing modify access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await;

        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [
                            "{\"eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_modify_removedattr": ["name"],
                        "acp_modify_presentattr": ["name"],
                        "acp_modify_class": ["object"]
                    }
                }"#,
            AccessControlModify
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("class", Value::new_class("access_control_modify")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlModify
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("class", Value::new_class("access_control_modify")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                ("acp_modify_removedattr", Value::new_iutf8("name")),
                ("acp_modify_presentattr", Value::new_iutf8("name")),
                ("acp_modify_class", Value::new_iutf8("object"))
            ),
            AccessControlModify
        );
    }

    #[qs_test]
    async fn test_access_acp_create_parser(qs: &QueryServer) {
        // Test that parsing create access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await;

        acp_from_entry_err!(
            &mut qs_write,
            r#"{
                    "attrs": {
                        "class": ["object", "access_control_profile"],
                        "name": ["acp_valid"],
                        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_receiver_group": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                        "acp_targetscope": [
                            "{\"eq\":[\"name\",\"a\"]}"
                        ],
                        "acp_create_class": ["object"],
                        "acp_create_attr": ["name"]
                    }
                }"#,
            AccessControlCreate
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("class", Value::new_class("access_control_create")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlCreate
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("access_control_profile")),
                ("class", Value::new_class("access_control_create")),
                ("name", Value::new_iname("acp_valid")),
                (
                    "uuid",
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_targetscope",
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                ("acp_create_attr", Value::new_iutf8("name")),
                ("acp_create_class", Value::new_iutf8("object"))
            ),
            AccessControlCreate
        );
    }

    #[qs_test]
    async fn test_access_acp_compound_parser(qs: &QueryServer) {
        // Test that parsing compound access controls works. This means that
        // given a single &str, we can evaluate all types from a single record.
        // This is valid, and could exist, IE a rule to allow create, search and modify
        // over a single scope.
        let mut qs_write = qs.write(duration_from_epoch_now()).await;

        let e = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("access_control_profile")),
            ("class", Value::new_class("access_control_create")),
            ("class", Value::new_class("access_control_delete")),
            ("class", Value::new_class("access_control_modify")),
            ("class", Value::new_class("access_control_search")),
            ("name", Value::new_iname("acp_valid")),
            (
                "uuid",
                Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (
                "acp_receiver_group",
                Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (
                "acp_targetscope",
                Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
            ),
            ("acp_search_attr", Value::new_iutf8("name")),
            ("acp_create_class", Value::new_iutf8("class")),
            ("acp_create_attr", Value::new_iutf8("name")),
            ("acp_modify_removedattr", Value::new_iutf8("name")),
            ("acp_modify_presentattr", Value::new_iutf8("name")),
            ("acp_modify_class", Value::new_iutf8("object"))
        );

        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlCreate);
        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlDelete);
        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlModify);
        acp_from_entry_ok!(&mut qs_write, e, AccessControlSearch);
    }

    macro_rules! test_acp_search {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .search_filter_entries(&mut $se, $entries)
                .expect("op failed");
            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    macro_rules! test_acp_search_reduce {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            // We still have to reduce the entries to be sure that we are good.
            let res = acw
                .search_filter_entries(&mut $se, $entries)
                .expect("operation failed");
            // Now on the reduced entries, reduce the entries attrs.
            let reduced = acw
                .search_filter_entry_attributes(&mut $se, res)
                .expect("operation failed");

            // Help the type checker for the expect set.
            let expect_set: Vec<Entry<EntryReduced, EntryCommitted>> = $expect
                .into_iter()
                .map(|e| unsafe { e.into_reduced() })
                .collect();

            debug!("expect --> {:?}", expect_set);
            debug!("result --> {:?}", reduced);
            // should be ok, and same as expect.
            assert!(reduced == expect_set);
        }};
    }

    #[test]
    fn test_access_internal_search() {
        // Test that an internal search bypasses ACS
        let se = unsafe { SearchEvent::new_internal_invalid(filter!(f_pres("class"))) };

        let expect = vec![E_TEST_ACCOUNT_1.clone()];
        let entries = vec![E_TEST_ACCOUNT_1.clone()];

        // This acp basically is "allow access to stuff, but not this".
        test_acp_search!(
            &se,
            vec![unsafe {
                AccessControlSearch::from_raw(
                    "test_acp",
                    Uuid::new_v4(),
                    UUID_TEST_GROUP_1,
                    filter_valid!(f_pres("nomatchy")), // apply to none - ie no allowed results
                    "name", // allow to this attr, but we don't eval this.
                )
            }],
            entries,
            expect
        );
    }

    #[test]
    fn test_access_enforce_search() {
        // Test that entries from a search are reduced by acps
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let ev2 = unsafe { E_TESTPERSON_2.clone().into_sealed_committed() };

        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        let se_a = unsafe {
            SearchEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_pres("name")),
            )
        };
        let ex_a = vec![Arc::new(ev1)];

        let se_b = unsafe {
            SearchEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_2.clone(),
                filter_all!(f_pres("name")),
            )
        };
        let ex_b = vec![];

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // Allow admin to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name",
            )
        };

        // Check the admin search event
        test_acp_search!(&se_a, vec![acp.clone()], r_set.clone(), ex_a);

        // Check the anonymous
        test_acp_search!(&se_b, vec![acp], r_set, ex_b);
    }

    #[test]
    fn test_access_enforce_scope_search() {
        sketching::test_init();
        // Test that identities are bound by their access scope.
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };

        let ex_some = vec![Arc::new(ev1.clone())];
        let ex_none = vec![];

        let r_set = vec![Arc::new(ev1)];

        let se_io = unsafe {
            SearchEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_identityonly(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_pres("name")),
            )
        };

        let se_ro = unsafe {
            SearchEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_pres("name")),
            )
        };

        let se_rw = unsafe {
            SearchEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_pres("name")),
            )
        };

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // Allow admin to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name",
            )
        };

        // Check the admin search event
        test_acp_search!(&se_io, vec![acp.clone()], r_set.clone(), ex_none);

        test_acp_search!(&se_ro, vec![acp.clone()], r_set.clone(), ex_some);

        test_acp_search!(&se_rw, vec![acp], r_set, ex_some);
    }

    #[test]
    fn test_access_enforce_scope_search_attrs() {
        // Test that in ident only mode that all attrs are always denied. The op should already have
        // "nothing to do" based on search_filter_entries, but we do the "right thing" anyway.

        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1)];

        let exv1 = unsafe { E_TESTPERSON_1_REDUCED.clone().into_sealed_committed() };

        let ex_anon_some = vec![exv1];
        let ex_anon_none: Vec<EntrySealedCommitted> = vec![];

        let se_anon_io = unsafe {
            SearchEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_identityonly(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_pres("name")),
            )
        };

        let se_anon_ro = unsafe {
            SearchEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_pres("name")),
            )
        };

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to all accounts.
                UUID_TEST_GROUP_1,
                // Allow anonymous to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name",
            )
        };

        // Finally test it!
        test_acp_search_reduce!(&se_anon_io, vec![acp.clone()], r_set.clone(), ex_anon_none);

        test_acp_search_reduce!(&se_anon_ro, vec![acp], r_set, ex_anon_some);
    }

    lazy_static! {
        pub static ref E_TESTPERSON_1_REDUCED: EntryInitNew =
            entry_init!(("name", Value::new_iname("testperson1")));
    }

    #[test]
    fn test_access_enforce_search_attrs() {
        // Test that attributes are correctly limited.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1)];

        let exv1 = unsafe { E_TESTPERSON_1_REDUCED.clone().into_sealed_committed() };
        let ex_anon = vec![exv1];

        let se_anon = unsafe {
            SearchEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to anonymous only
                UUID_TEST_GROUP_1,
                // Allow anonymous to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name",
            )
        };

        // Finally test it!
        test_acp_search_reduce!(&se_anon, vec![acp], r_set, ex_anon);
    }

    #[test]
    fn test_access_enforce_search_attrs_req() {
        // Test that attributes are correctly limited by the request.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };

        let r_set = vec![Arc::new(ev1)];

        let exv1 = unsafe { E_TESTPERSON_1_REDUCED.clone().into_sealed_committed() };
        let ex_anon = vec![exv1];

        let mut se_anon = unsafe {
            SearchEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };
        // the requested attrs here.
        se_anon.attrs = Some(btreeset![AttrString::from("name")]);

        let acp = unsafe {
            AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to anonymous only
                UUID_TEST_GROUP_1,
                // Allow anonymous to read only testperson1
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // In that read, admin may only view the "name" attribute, or query on
                // the name attribute. Any other query (should be) rejected.
                "name uuid",
            )
        };

        // Finally test it!
        test_acp_search_reduce!(&se_anon, vec![acp], r_set, ex_anon);
    }

    macro_rules! test_acp_modify {
        (
            $me:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_modify($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .modify_allow_operation(&mut $me, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_enforce_modify() {
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1)];

        // Name present
        let me_pres = unsafe {
            ModifyEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_pres("name", &Value::new_iname("value"))]),
            )
        };
        // Name rem
        let me_rem = unsafe {
            ModifyEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_remove("name", &PartialValue::new_iname("value"))]),
            )
        };
        // Name purge
        let me_purge = unsafe {
            ModifyEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_purge("name")]),
            )
        };

        // Class account pres
        let me_pres_class = unsafe {
            ModifyEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_pres("class", &Value::new_class("account"))]),
            )
        };
        // Class account rem
        let me_rem_class = unsafe {
            ModifyEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_remove("class", &PartialValue::new_class("account"))]),
            )
        };
        // Class purge
        let me_purge_class = unsafe {
            ModifyEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_purge("class")]),
            )
        };

        // Allow name and class, class is account
        let acp_allow = unsafe {
            AccessControlModify::from_raw(
                "test_modify_allow",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // Allow pres name and class
                "name class",
                // Allow rem name and class
                "name class",
                // And the class allowed is account
                "account",
            )
        };
        // Allow member, class is group. IE not account
        let acp_deny = unsafe {
            AccessControlModify::from_raw(
                "test_modify_deny",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // Allow pres name and class
                "member class",
                // Allow rem name and class
                "member class",
                // And the class allowed is account
                "group",
            )
        };
        // Does not have a pres or rem class in attrs
        let acp_no_class = unsafe {
            AccessControlModify::from_raw(
                "test_modify_no_class",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // Allow pres name and class
                "name class",
                // Allow rem name and class
                "name class",
                // And the class allowed is NOT an account ...
                "group",
            )
        };

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r_set, true);

        // Test rejected pres
        test_acp_modify!(&me_pres, vec![acp_deny.clone()], &r_set, false);
        // Test rejected rem
        test_acp_modify!(&me_rem, vec![acp_deny.clone()], &r_set, false);
        // Test rejected purge
        test_acp_modify!(&me_purge, vec![acp_deny.clone()], &r_set, false);

        // test allowed pres class
        test_acp_modify!(&me_pres_class, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem class
        test_acp_modify!(&me_rem_class, vec![acp_allow.clone()], &r_set, true);
        // test reject purge-class even if class present in allowed remattrs
        test_acp_modify!(&me_purge_class, vec![acp_allow], &r_set, false);

        // Test reject pres class, but class not in classes
        test_acp_modify!(&me_pres_class, vec![acp_no_class.clone()], &r_set, false);
        // Test reject pres class, class in classes but not in pres attrs
        test_acp_modify!(&me_pres_class, vec![acp_deny.clone()], &r_set, false);
        // test reject rem class, but class not in classes
        test_acp_modify!(&me_rem_class, vec![acp_no_class], &r_set, false);
        // test reject rem class, class in classes but not in pres attrs
        test_acp_modify!(&me_rem_class, vec![acp_deny], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_modify() {
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1)];

        // Name present
        let me_pres_io = unsafe {
            ModifyEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_identityonly(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_pres("name", &Value::new_iname("value"))]),
            )
        };

        // Name present
        let me_pres_ro = unsafe {
            ModifyEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_pres("name", &Value::new_iname("value"))]),
            )
        };

        // Name present
        let me_pres_rw = unsafe {
            ModifyEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
                modlist!([m_pres("name", &Value::new_iname("value"))]),
            )
        };

        let acp_allow = unsafe {
            AccessControlModify::from_raw(
                "test_modify_allow",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // To modify testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // Allow pres name and class
                "name class",
                // Allow rem name and class
                "name class",
                // And the class allowed is account
                "account",
            )
        };

        test_acp_modify!(&me_pres_io, vec![acp_allow.clone()], &r_set, false);

        test_acp_modify!(&me_pres_ro, vec![acp_allow.clone()], &r_set, false);

        test_acp_modify!(&me_pres_rw, vec![acp_allow], &r_set, true);
    }

    macro_rules! test_acp_create {
        (
            $ce:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_create($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .create_allow_operation(&mut $ce, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_enforce_create() {
        let ev1 = entry_init!(
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            ("class", Value::new_class("account")),
            ("notallowed", Value::new_class("notallowed")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );

        let r2_set = vec![ev2];

        let ev3 = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("notallowed")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r3_set = vec![ev3];

        let ev4 = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r4_set = vec![ev4];

        // In this case, we can make the create event with an empty entry
        // set because we only reference the entries in r_set in the test.
        //
        // In the server code, the entry set is derived from and checked
        // against the create event, so we have some level of trust in it.

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = unsafe {
            AccessControlCreate::from_raw(
                "test_create",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To create matching filter testperson
                // Can this be empty?
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // classes
                "account",
                // attrs
                "class name uuid",
            )
        };

        let acp2 = unsafe {
            AccessControlCreate::from_raw(
                "test_create_2",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To create matching filter testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // classes
                "group",
                // attrs
                "class name uuid",
            )
        };

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test reject create (not allowed attr)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
        // Test reject create (not allowed class)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r3_set, false);
        // Test reject create (hybrid u + g entry w_ u & g create allow)
        test_acp_create!(&ce_admin, vec![acp, acp2], &r4_set, false);
    }

    #[test]
    fn test_access_enforce_scope_create() {
        let ev1 = entry_init!(
            ("class", Value::new_class("account")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let admin = E_TEST_ACCOUNT_1.clone();

        let ce_admin_io = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_identityonly(admin.clone()),
            vec![],
        );

        let ce_admin_ro = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(admin.clone()),
            vec![],
        );

        let ce_admin_rw = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(admin),
            vec![],
        );

        let acp = unsafe {
            AccessControlCreate::from_raw(
                "test_create",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To create matching filter testperson
                // Can this be empty?
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // classes
                "account",
                // attrs
                "class name uuid",
            )
        };

        test_acp_create!(&ce_admin_io, vec![acp.clone()], &r1_set, false);

        test_acp_create!(&ce_admin_ro, vec![acp.clone()], &r1_set, false);

        test_acp_create!(&ce_admin_rw, vec![acp], &r1_set, true);
    }

    macro_rules! test_acp_delete {
        (
            $de:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_delete($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .delete_allow_operation($de, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_enforce_delete() {
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1)];

        let de_admin = unsafe {
            DeleteEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        let de_anon = unsafe {
            DeleteEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_2.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        let acp = unsafe {
            AccessControlDelete::from_raw(
                "test_delete",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To delete testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r_set, true);
        // Test reject delete
        test_acp_delete!(&de_anon, vec![acp], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_delete() {
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1)];

        let admin = E_TEST_ACCOUNT_1.clone();

        let de_admin_io = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_identityonly(admin.clone()),
            filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
        );

        let de_admin_ro = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(admin.clone()),
            filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
        );

        let de_admin_rw = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(admin),
            filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
        );

        let acp = unsafe {
            AccessControlDelete::from_raw(
                "test_delete",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To delete testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        test_acp_delete!(&de_admin_io, vec![acp.clone()], &r_set, false);

        test_acp_delete!(&de_admin_ro, vec![acp.clone()], &r_set, false);

        test_acp_delete!(&de_admin_rw, vec![acp], &r_set, true);
    }

    macro_rules! test_acp_effective_permissions {
        (
            $ident:expr,
            $attrs:expr,
            $search_controls:expr,
            $modify_controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_search($search_controls)
                .expect("Failed to update");
            acw.update_modify($modify_controls)
                .expect("Failed to update");
            let acw = acw;

            let res = acw
                .effective_permission_check($ident, $attrs, $entries)
                .expect("Failed to apply effective_permission_check");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert!(res == $expect);
        }};
    }

    #[test]
    fn test_access_effective_permission_check_1() {
        sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_sealed_committed() };

        let r_set = vec![Arc::new(ev1)];

        test_acp_effective_permissions!(
            &admin,
            None,
            vec![unsafe {
                AccessControlSearch::from_raw(
                    "test_acp",
                    Uuid::new_v4(),
                    // apply to admin only
                    UUID_TEST_GROUP_1,
                    // Allow admin to read only testperson1
                    filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    // They can read "name".
                    "name",
                )
            }],
            vec![],
            &r_set,
            vec![AccessEffectivePermission {
                delete: false,
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: Access::Allow(btreeset![AttrString::from("name")]),
                modify_pres: Access::Allow(BTreeSet::new()),
                modify_rem: Access::Allow(BTreeSet::new()),
                modify_class: Access::Allow(BTreeSet::new()),
            }]
        )
    }

    #[test]
    fn test_access_effective_permission_check_2() {
        sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_sealed_committed() };

        let r_set = vec![Arc::new(ev1)];

        test_acp_effective_permissions!(
            &admin,
            None,
            vec![],
            vec![unsafe {
                AccessControlModify::from_raw(
                    "test_acp",
                    Uuid::new_v4(),
                    // apply to admin only
                    UUID_TEST_GROUP_1,
                    // Allow admin to read only testperson1
                    filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                    // They can read "name".
                    "name",
                    "name",
                    "object",
                )
            }],
            &r_set,
            vec![AccessEffectivePermission {
                delete: false,
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: Access::Allow(BTreeSet::new()),
                modify_pres: Access::Allow(btreeset![AttrString::from("name")]),
                modify_rem: Access::Allow(btreeset![AttrString::from("name")]),
                modify_class: Access::Allow(btreeset![AttrString::from("object")]),
            }]
        )
    }

    #[test]
    fn test_access_sync_authority_create() {
        sketching::test_init();

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        // We can create without a sync class.
        let ev1 = entry_init!(
            ("class", CLASS_ACCOUNT.clone()),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            ("class", CLASS_ACCOUNT.clone()),
            ("class", CLASS_SYNC_OBJECT.clone()),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r2_set = vec![ev2];

        let acp = unsafe {
            AccessControlCreate::from_raw(
                "test_create",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To create matching filter testperson
                // Can this be empty?
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
                // classes
                "account sync_object",
                // attrs
                "class name uuid",
            )
        };

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test Fails due to protected from sync object
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
    }

    #[test]
    fn test_access_sync_authority_delete() {
        sketching::test_init();

        let ev1 = unsafe {
            entry_init!(
                ("class", CLASS_ACCOUNT.clone()),
                ("name", Value::new_iname("testperson1")),
                ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
            )
            .into_sealed_committed()
        };
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = unsafe {
            entry_init!(
                ("class", CLASS_ACCOUNT.clone()),
                ("class", CLASS_SYNC_OBJECT.clone()),
                ("name", Value::new_iname("testperson1")),
                ("uuid", Value::Uuid(UUID_TEST_ACCOUNT_1))
            )
            .into_sealed_committed()
        };
        let r2_set = vec![Arc::new(ev2)];

        let de_admin = unsafe {
            DeleteEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        let acp = unsafe {
            AccessControlDelete::from_raw(
                "test_delete",
                Uuid::new_v4(),
                // Apply to admin
                UUID_TEST_GROUP_1,
                // To delete testperson
                filter_valid!(f_eq("name", PartialValue::new_iname("testperson1"))),
            )
        };

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r1_set, true);
        // Test reject delete
        test_acp_delete!(&de_admin, vec![acp], &r2_set, false);
    }
}
