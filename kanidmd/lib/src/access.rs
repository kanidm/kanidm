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

// use concread::collections::bptree::*;
// use hashbrown::HashSet;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ops::DerefMut;
use std::sync::Arc;

use concread::arcache::{ARCache, ARCacheBuilder, ARCacheReadTxn};
use concread::cowcell::*;
use kanidm_proto::v1::{Filter as ProtoFilter, OperationError};
use tracing::trace;
use uuid::Uuid;

use crate::entry::{Entry, EntryCommitted, EntryInit, EntryNew, EntryReduced, EntrySealed};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
use crate::filter::{Filter, FilterValid, FilterValidResolved};
use crate::identity::{AccessScope, IdentType, IdentityId};
use crate::modify::Modify;
use crate::prelude::*;

const ACP_RESOLVE_FILTER_CACHE_MAX: usize = 2048;
const ACP_RESOLVE_FILTER_CACHE_LOCAL: usize = 16;

// =========================================================================
// PARSE ENTRY TO ACP, AND ACP MANAGEMENT
// =========================================================================

#[derive(Debug, Clone)]
pub struct AccessControlSearch {
    acp: AccessControlProfile,
    attrs: BTreeSet<AttrString>,
}

impl AccessControlSearch {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality("class", &PVCLASS_ACS) {
            admin_error!("class access_control_search not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_search".to_string(),
            ));
        }

        let attrs = value
            .get_ava_iter_iutf8("acp_search_attr")
            .ok_or_else(|| {
                admin_error!("Missing acp_search_attr");
                OperationError::InvalidAcpState("Missing acp_search_attr".to_string())
            })?
            .map(AttrString::from)
            .collect();

        let acp = AccessControlProfile::try_from(qs, value)?;

        Ok(AccessControlSearch { acp, attrs })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        attrs: &str,
    ) -> Self {
        AccessControlSearch {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: Some(receiver),
                targetscope,
            },
            attrs: attrs
                .split_whitespace()
                .map(|s| AttrString::from(s))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlDelete {
    acp: AccessControlProfile,
}

impl AccessControlDelete {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality("class", &PVCLASS_ACD) {
            admin_error!("class access_control_delete not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_delete".to_string(),
            ));
        }

        Ok(AccessControlDelete {
            acp: AccessControlProfile::try_from(qs, value)?,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
    ) -> Self {
        AccessControlDelete {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: Some(receiver),
                targetscope,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlCreate {
    acp: AccessControlProfile,
    classes: Vec<AttrString>,
    attrs: Vec<AttrString>,
}

impl AccessControlCreate {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality("class", &PVCLASS_ACC) {
            admin_error!("class access_control_create not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_create".to_string(),
            ));
        }

        let attrs = value
            .get_ava_iter_iutf8("acp_create_attr")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let classes = value
            .get_ava_iter_iutf8("acp_create_class")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        Ok(AccessControlCreate {
            acp: AccessControlProfile::try_from(qs, value)?,
            classes,
            attrs,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        classes: &str,
        attrs: &str,
    ) -> Self {
        AccessControlCreate {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: Some(receiver),
                targetscope,
            },
            classes: classes.split_whitespace().map(AttrString::from).collect(),
            attrs: attrs.split_whitespace().map(AttrString::from).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessControlModify {
    acp: AccessControlProfile,
    classes: Vec<AttrString>,
    presattrs: Vec<AttrString>,
    remattrs: Vec<AttrString>,
}

impl AccessControlModify {
    pub fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality("class", &PVCLASS_ACM) {
            admin_error!("class access_control_modify not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_modify".to_string(),
            ));
        }

        let presattrs = value
            .get_ava_iter_iutf8("acp_modify_presentattr")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let remattrs = value
            .get_ava_iter_iutf8("acp_modify_removedattr")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let classes = value
            .get_ava_iter_iutf8("acp_modify_class")
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        Ok(AccessControlModify {
            acp: AccessControlProfile::try_from(qs, value)?,
            classes,
            presattrs,
            remattrs,
        })
    }

    #[cfg(test)]
    unsafe fn from_raw(
        name: &str,
        uuid: Uuid,
        receiver: Uuid,
        targetscope: Filter<FilterValid>,
        presattrs: &str,
        remattrs: &str,
        classes: &str,
    ) -> Self {
        AccessControlModify {
            acp: AccessControlProfile {
                name: name.to_string(),
                uuid,
                receiver: Some(receiver),
                targetscope,
            },
            classes: classes
                .split_whitespace()
                .map(|s| AttrString::from(s))
                .collect(),
            presattrs: presattrs
                .split_whitespace()
                .map(|s| AttrString::from(s))
                .collect(),
            remattrs: remattrs
                .split_whitespace()
                .map(|s| AttrString::from(s))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct AccessControlProfile {
    name: String,
    // Currently we retrieve this but don't use it. We could depending on how we change
    // the acp update routine.
    #[allow(dead_code)]
    uuid: Uuid,
    // Must be
    //   Group
    // === ⚠️   WARNING!!! ⚠️  ===
    // This is OPTION to allow migration from 10 -> 11. We have to do this because ACP is reloaded
    // so early in the boot phase that we can't have migrated the content of the receiver yet! As a
    // result we MUST be able to withstand some failure in the parse process. The INTENT is that
    // during early boot this will be None, and will NEVER match. Once started, the migration
    // will occur, and this will flip to Some. In a future version we can remove this!
    receiver: Option<Uuid>,
    // or
    //  Filter
    //  Group
    //  Self
    // and
    //  exclude
    //    Group
    targetscope: Filter<FilterValid>,
}

impl AccessControlProfile {
    fn try_from(
        qs: &mut QueryServerWriteTransaction,
        value: &Entry<EntrySealed, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        // Assert we have class access_control_profile
        if !value.attribute_equality("class", &PVCLASS_ACP) {
            admin_error!("class access_control_profile not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_profile".to_string(),
            ));
        }

        // copy name
        let name = value
            .get_ava_single_iname("name")
            .ok_or_else(|| {
                admin_error!("Missing name");
                OperationError::InvalidAcpState("Missing name".to_string())
            })?
            .to_string();
        // copy uuid
        let uuid = value.get_uuid();
        // receiver, and turn to real filter

        // === ⚠️   WARNING!!! ⚠️  ===
        // See struct ACP for details.
        let receiver = value.get_ava_single_refer("acp_receiver_group");
        /*
        .ok_or_else(|| {
            admin_error!("Missing acp_receiver_group");
            OperationError::InvalidAcpState("Missing acp_receiver_group".to_string())
        })?;
        */

        // targetscope, and turn to real filter
        let targetscope_f: ProtoFilter = value
            .get_ava_single_protofilter("acp_targetscope")
            // .map(|pf| pf.clone())
            .cloned()
            .ok_or_else(|| {
                admin_error!("Missing acp_targetscope");
                OperationError::InvalidAcpState("Missing acp_targetscope".to_string())
            })?;

        let ident = Identity::from_internal();

        let targetscope_i = Filter::from_rw(&ident, &targetscope_f, qs).map_err(|e| {
            admin_error!("Targetscope validation failed {:?}", e);
            e
        })?;

        let targetscope = targetscope_i.validate(qs.get_schema()).map_err(|e| {
            admin_error!("acp_targetscope Schema Violation {:?}", e);
            OperationError::SchemaViolation(e)
        })?;

        Ok(AccessControlProfile {
            name,
            uuid,
            receiver,
            targetscope,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEffectivePermission {
    // I don't think we need this? The ident is implied by the requestor.
    // ident: Uuid,
    pub target: Uuid,
    pub search: BTreeSet<AttrString>,
    pub modify_pres: BTreeSet<AttrString>,
    pub modify_rem: BTreeSet<AttrString>,
    pub modify_class: BTreeSet<AttrString>,
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
    // fn get_acp_related_search_cache(&self) -> &mut ARCacheReadTxn<'a, Uuid, Vec<Uuid>>;
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
        // let acp_related_search_cache = self.get_acp_related_search_cache();
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

        /*
        // Stash the uuids into the cache.
        let mut acs_uuids: Vec<Uuid> = related_acp.iter().map(|acs| acs.acp.uuid).collect();
        acs_uuids.sort_unstable();
        acp_related_search_cache.insert(*rec_entry.get_uuid(), acs_uuids);
        */

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
        // If this is an internal search, return our working set.
        match &se.ident.origin {
            IdentType::Internal => {
                trace!("Internal operation, bypassing access check");
                // No need to check ACS
                return Ok(entries);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(_) => {}
        };
        info!(event = %se.ident, "Access check for search (filter) event");

        match se.ident.access_scope() {
            AccessScope::IdentityOnly | AccessScope::Synchronise => {
                security_access!("denied ❌ - identity access scope is not permitted to search");
                return Ok(vec![]);
            }
            AccessScope::ReadOnly | AccessScope::ReadWrite => {
                // As you were
            }
        };

        // First get the set of acps that apply to this receiver
        let related_acp: Vec<(&AccessControlSearch, _)> = self.search_related_acp(&se.ident);

        /*
        related_acp.iter().for_each(|racp| {
            security_access!(acs = ?racp.acp.name, "Event Origin Related acs");
        });
        */

        // Get the set of attributes requested by this se filter. This is what we are
        // going to access check.
        let requested_attrs: BTreeSet<&str> = se.filter_orig.get_attr_set();

        // For each entry
        let allowed_entries: Vec<Arc<EntrySealedCommitted>> =
                    entries
                                    .into_iter()
                                    .filter(|e| {
                                        // For each acp
                                        let allowed_attrs: BTreeSet<&str> = related_acp
                                            .iter()
                                            .filter_map(|(acs, f_res)| {
                                                // if it applies
                                                if e.entry_match_no_index(f_res) {
                                                    security_access!(entry = ?e.get_uuid(), acs = %acs.acp.name, "entry matches acs");
                                                    // add search_attrs to allowed.
                                                    Some(acs.attrs.iter().map(|s| s.as_str()))
                                                } else {
                                                    trace!(entry = ?e.get_uuid(), acs = %acs.acp.name, "entry DOES NOT match acs"); // should this be `security_access`?
                                                    None
                                                }
                                            })
                                            .flatten()
                                            .collect();

                                        security_access!(
                                            requested = ?requested_attrs,
                                            allows = ?allowed_attrs,
                                            "attributes",
                                        );

                                        // is attr set a subset of allowed set?
                                        // true -> entry is allowed in result set
                                        // false -> the entry is not allowed to be searched by this entity, so is
                                        //          excluded.
                                        let decision = requested_attrs.is_subset(&allowed_attrs);
                                        security_access!(?decision, "search attr decision");
                                        decision
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
        // If this is an internal search, do nothing. This can occur in some test cases ONLY
        match &se.ident.origin {
            IdentType::Internal => {
                if cfg!(test) {
                    trace!("TEST: Internal search in external interface - allowing due to cfg test ...");
                    // In tests we just push everything back.
                    return Ok(entries
                        .into_iter()
                        .map(|e| unsafe { e.as_ref().clone().into_reduced() })
                        .collect());
                } else {
                    // In production we can't risk leaking data here, so we return
                    // empty sets.
                    security_critical!("IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                    // No need to check ACS
                    return Ok(Vec::new());
                }
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(_) => {}
        };

        /*
         * Super similar to above (could even re-use some parts). Given a set of entries,
         * reduce the attribute sets on them to "what is visible". This is ONLY called on
         * the server edge, such that clients only see what they can, but internally,
         * impersonate and such actually still get the whole entry back as not to break
         * modify and co.
         */

        info!(event = %se.ident, "Access check for search (reduce) event");

        // Get the relevant acps for this receiver.
        let related_acp: Vec<(&AccessControlSearch, _)> = self.search_related_acp(&se.ident);
        let related_acp: Vec<(&AccessControlSearch, _)> = if let Some(r_attrs) = se.attrs.as_ref() {
            related_acp
                .into_iter()
                .filter(|(acs, _)| !acs.attrs.is_disjoint(r_attrs))
                .collect()
        } else {
            related_acp
        };

        /*
        related_acp.iter().for_each(|racp| {
            lsecurity_access!( "Related acs -> {:?}", racp.acp.name);
        });
        */

        // Build a reference set from the req_attrs. This is what we test against
        // to see if the attribute is something we currently want.
        let req_attrs: Option<BTreeSet<_>> = se
            .attrs
            .as_ref()
            .map(|vs| vs.iter().map(|s| s.as_str()).collect());

        //  For each entry
        let allowed_entries: Vec<Entry<EntryReduced, EntryCommitted>> = entries
            .into_iter()
            .map(|e| {
                // Get the set of attributes you can see for this entry
                // this is within your related acp scope.
                let allowed_attrs: BTreeSet<&str> = related_acp
                    .iter()
                    .filter_map(|(acs, f_res)| {
                        if e.entry_match_no_index(f_res) {
                            security_access!(
                                target = ?e.get_uuid(),
                                acs = %acs.acp.name,
                                "target entry matches acs",
                            );
                            // add search_attrs to allowed iterator
                            Some(acs.attrs.iter().map(|s| s.as_str()).filter(|s| {
                                req_attrs
                                    .as_ref()
                                    .map(|r_attrs| r_attrs.contains(s))
                                    .unwrap_or(true)
                            }))
                        } else {
                            trace!(
                                target = ?e.get_uuid(),
                                acs = %acs.acp.name,
                                "target entry DOES NOT match acs",
                            );
                            None
                        }
                    })
                    .flatten()
                    .collect();

                // Remove all others that are present on the entry.
                security_access!(
                    requested = ?req_attrs,
                    allowed = ?allowed_attrs,
                    "attributes"
                );

                // Now purge the attrs that are NOT allowed.
                e.reduce_attributes(&allowed_attrs)
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

    #[allow(clippy::cognitive_complexity)]
    #[instrument(level = "debug", name = "access::modify_allow_operation", skip_all)]
    fn modify_allow_operation(
        &self,
        me: &ModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        match &me.ident.origin {
            IdentType::Internal => {
                trace!("Internal operation, bypassing access check");
                // No need to check ACS
                return Ok(true);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(_) => {}
        };
        info!(event = %me.ident, "Access check for modify event");

        match me.ident.access_scope() {
            AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::Synchronise => {
                security_access!("denied ❌ - identity access scope is not permitted to modify");
                return Ok(false);
            }
            AccessScope::ReadWrite => {
                // As you were
            }
        };

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

        related_acp.iter().for_each(|racp| {
            trace!("Related acs -> {:?}", racp.0.acp.name);
        });

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
                        // existance, and second, we would have failed the mod at schema checking
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
            // For this entry, find the acp's that apply to it from the
            // set that apply to the entry that is performing the operation
            let scoped_acp: Vec<&AccessControlModify> = related_acp
                .iter()
                .filter_map(|(acm, f_res)| {
                    if e.entry_match_no_index(f_res) {
                        Some(*acm)
                    } else {
                        None
                    }
                })
                .collect();
            // Build the sets of classes, pres and rem we are allowed to modify, extend
            // or use based on the set of matched acps.
            let allowed_pres: BTreeSet<&str> = scoped_acp
                .iter()
                .flat_map(|acp| acp.presattrs.iter().map(|v| v.as_str()))
                .collect();

            let allowed_rem: BTreeSet<&str> = scoped_acp
                .iter()
                .flat_map(|acp| acp.remattrs.iter().map(|v| v.as_str()))
                .collect();

            let allowed_classes: BTreeSet<&str> = scoped_acp
                .iter()
                .flat_map(|acp| acp.classes.iter().map(|v| v.as_str()))
                .collect();

            // Now check all the subsets are true. Remember, purge class
            // is already checked above.
            if !requested_pres.is_subset(&allowed_pres) {
                security_access!("requested_pres is not a subset of allowed");
                security_access!(
                    "requested_pres: {:?} !⊆ allowed: {:?}",
                    requested_pres,
                    allowed_pres
                );
                false
            } else if !requested_rem.is_subset(&allowed_rem) {
                security_access!("requested_rem is not a subset of allowed");
                security_access!(
                    "requested_rem: {:?} !⊆ allowed: {:?}",
                    requested_rem,
                    allowed_rem
                );
                false
            } else if !requested_classes.is_subset(&allowed_classes) {
                security_access!("requested_classes is not a subset of allowed");
                security_access!(
                    "requested_classes: {:?} !⊆ allowed: {:?}",
                    requested_classes,
                    allowed_classes
                );
                false
            } else {
                security_access!("passed pres, rem, classes check.");
                true
            } // if acc == false
        });
        if r {
            security_access!("allowed ✅");
        } else {
            security_access!("denied ❌");
        }
        Ok(r)
    }

    #[allow(clippy::cognitive_complexity)]
    #[instrument(level = "debug", name = "access::create_allow_operation", skip_all)]
    fn create_allow_operation(
        &self,
        ce: &CreateEvent,
        entries: &[Entry<EntryInit, EntryNew>],
    ) -> Result<bool, OperationError> {
        match &ce.ident.origin {
            IdentType::Internal => {
                trace!("Internal operation, bypassing access check");
                // No need to check ACS
                return Ok(true);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(_) => {}
        };
        info!(event = %ce.ident, "Access check for create event");

        match ce.ident.access_scope() {
            AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::Synchronise => {
                security_access!("denied ❌ - identity access scope is not permitted to create");
                return Ok(false);
            }
            AccessScope::ReadWrite => {
                // As you were
            }
        };

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

        // lsecurity_access!( "Related acc -> {:?}", related_acp);

        // For each entry
        let r = entries.iter().all(|e| {
            // Build the set of requested classes and attrs here.
            let create_attrs: BTreeSet<&str> = e.get_ava_names().collect();
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

            let create_classes: BTreeSet<&str> = match e.get_ava_iter_iutf8("class") {
                Some(s) => s.collect(),
                None => {
                    admin_error!("Class set failed to build - corrupted entry?");
                    return false;
                }
            };

            related_acp.iter().any(|(accr, f_res)| {
                // Check to see if allowed.
                if e.entry_match_no_index(f_res) {
                    security_access!(?e, acs = ?accr, "entry matches acs");
                    // It matches, so now we have to check attrs and classes.
                    // Remember, we have to match ALL requested attrs
                    // and classes to pass!
                    let allowed_attrs: BTreeSet<&str> =
                        accr.attrs.iter().map(|s| s.as_str()).collect();
                    let allowed_classes: BTreeSet<&str> =
                        accr.classes.iter().map(|s| s.as_str()).collect();

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
                    trace!(?e, acs = %accr.acp.name, "entry DOES NOT match acs");
                    // Does not match, fail this rule.
                    false
                }
            })
            //      Find the set of related acps for this entry.
            //
            //      For each "created" entry.
            //          If the created entry is 100% allowed by this acp
            //          IE: all attrs to be created AND classes match classes
            //              allow
            //          if no acp allows, fail operation.
        });

        if r {
            security_access!("allowed ✅");
        } else {
            security_access!("denied ❌");
        }

        Ok(r)
    }

    #[instrument(level = "debug", name = "access::delete_allow_operation", skip_all)]
    fn delete_allow_operation(
        &self,
        de: &DeleteEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        match &de.ident.origin {
            IdentType::Internal => {
                trace!("Internal operation, bypassing access check");
                // No need to check ACS
                return Ok(true);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(_) => {}
        };
        info!(event = %de.ident, "Access check for delete event");

        match de.ident.access_scope() {
            AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::Synchronise => {
                security_access!("denied ❌ - identity access scope is not permitted to delete");
                return Ok(false);
            }
            AccessScope::ReadWrite => {
                // As you were
            }
        };

        // Some useful references we'll use for the remainder of the operation
        let delete_state = self.get_delete();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        // Find the acps that relate to the caller.
        let related_acp: Vec<(&AccessControlDelete, _)> = delete_state
            .iter()
            .filter_map(|acs| {
                if let Some(receiver) = acs.acp.receiver {
                    if de.ident.is_memberof(receiver) {
                        acs.acp
                            .targetscope
                            .resolve(&de.ident, None, Some(acp_resolve_filter_cache))
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

        /*
        related_acp.iter().for_each(|racp| {
            lsecurity_access!( "Related acs -> {:?}", racp.acp.name);
        });
        */

        // For each entry
        let r = entries.iter().all(|e| {
            related_acp.iter().any(|(acd, f_res)| {
                if e.entry_match_no_index(f_res) {
                    security_access!(
                        entry_uuid = ?e.get_uuid(),
                        acs = %acd.acp.name,
                        "entry matches acs"
                    );
                    // It matches, so we can delete this!
                    security_access!("passed");
                    true
                } else {
                    trace!(
                        "entry {:?} DOES NOT match acs {}",
                        e.get_uuid(),
                        acd.acp.name
                    );
                    // Does not match, fail.
                    false
                } // else
            }) // any related_acp
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
        // as seperate attrs to describe what is capable.

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
        // I think we seperate this to multiple checks ...?

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

        /*
        search_related_acp.iter().for_each(|(racp, _)| {
            trace!("Related acs -> {:?}", racp.acp.name);
        });
        */

        // == modify ==

        let modify_related_acp: Vec<(&AccessControlModify, _)> = self.modify_related_acp(ident);

        /*
        modify_related_acp.iter().for_each(|(racp, _)| {
            trace!("Related acm -> {:?}", racp.acp.name);
        });
        */

        let effective_permissions: Vec<_> = entries
            .iter()
            .map(|e| {
                // == search ==
                let allowed_attrs: BTreeSet<AttrString> = search_related_acp
                    .iter()
                    .filter_map(|(acs, f_res)| {
                        // if it applies
                        if e.entry_match_no_index(f_res) {
                            // security_access!(entry = ?e.get_uuid(), acs = %acs.acp.name, "entry matches acs");
                            Some(acs.attrs.iter().cloned())
                        } else {
                            trace!(entry = ?e.get_uuid(), acs = %acs.acp.name, "entry DOES NOT match acs"); // should this be `security_access`?
                            None
                        }
                    })
                    .flatten()
                    .collect();

                security_access!(
                    requested = ?attrs,
                    allows = ?allowed_attrs,
                    "attributes",
                );

                // intersect?
                let search_effective = if let Some(r_attrs) = attrs.as_ref() {
                    r_attrs & &allowed_attrs
                } else {
                    allowed_attrs
                };

                // == modify ==
                let modify_scoped_acp: Vec<&AccessControlModify> = modify_related_acp
                    .iter()
                    .filter_map(|(acm, f_res)| {
                        if e.entry_match_no_index(f_res) {
                            Some(*acm)
                        } else {
                            None
                        }
                    })
                    .collect();

                let modify_pres: BTreeSet<AttrString> = modify_scoped_acp
                    .iter()
                    .flat_map(|acp| acp.presattrs.iter().cloned())
                    .collect();

                let modify_rem: BTreeSet<AttrString> = modify_scoped_acp
                    .iter()
                    .flat_map(|acp| acp.remattrs.iter().cloned())
                    .collect();

                let modify_class: BTreeSet<AttrString> = modify_scoped_acp
                    .iter()
                    .flat_map(|acp| acp.classes.iter().cloned())
                    .collect();

                AccessEffectivePermission {
                    target: e.get_uuid(),
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
    // acp_related_search_cache_wr: ARCacheWriteTxn<'a, Uuid, Vec<Uuid>>,
    // acp_related_search_cache: Cell<ARCacheReadTxn<'a, Uuid, Vec<Uuid>>>,
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
        // Clear the existing tree. We don't care that we are wiping it
        // because we have the transactions to protect us from errors
        // to allow rollbacks.
        /*
        let acps_search = &mut self.inner.deref_mut().acps_search;
        acps_search.clear();
        for acp in acps {
            let uuid = acp.acp.uuid;
            acps_search.insert(uuid, acp);
        }
        */
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_search);
        // We reloaded the search acps, so we need to ditch all the cache.
        // self.acp_related_search_cache_wr.clear();
        Ok(())
    }

    /*
    pub fn invalidate_related_cache(&mut self, inv: &[Uuid]) {
        inv.iter()
            .for_each(|uuid| self.acp_related_search_cache_wr.remove(*uuid))
    }
    */

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
        // self.acp_related_search_cache_wr.commit();
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

    /*
    fn get_acp_related_search_cache(&self) -> &mut ARCacheReadTxn<'a, Uuid, Vec<Uuid>> {
        unsafe {
            let mptr = self.acp_related_search_cache.as_ptr();
            &mut (*mptr) as &mut ARCacheReadTxn<'a, Uuid, Vec<Uuid>>
        }
    }
    */

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

    /*
    fn get_acp_related_search_cache(&self) -> &mut ARCacheReadTxn<'a, Uuid, Vec<Uuid>> {
        unsafe {
            let mptr = self.acp_related_search_cache.as_ptr();
            &mut (*mptr) as &mut ARCacheReadTxn<'a, Uuid, Vec<Uuid>>
        }
    }
    */

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

impl AccessControls {
    #![allow(clippy::expect_used)]
    pub fn new() -> Self {
        AccessControls {
            inner: CowCell::new(AccessControlsInner {
                acps_search: Vec::new(),
                acps_create: Vec::new(),
                acps_modify: Vec::new(),
                acps_delete: Vec::new(),
            }),
            // Allow the expect, if this fails it reperesents a programming/development
            // failure.
            acp_resolve_filter_cache: ARCacheBuilder::new()
                .set_size(ACP_RESOLVE_FILTER_CACHE_MAX, ACP_RESOLVE_FILTER_CACHE_LOCAL)
                .set_reader_quiesce(true)
                .build()
                .expect("Failed to construct acp_resolve_filter_cache"),
        }
    }

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

    use crate::access::{
        AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlProfile,
        AccessControlSearch, AccessControls, AccessControlsTransaction, AccessEffectivePermission,
    };
    use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
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
                ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_1)),
                ("memberof", Value::new_refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed()
        });
        pub static ref E_TEST_ACCOUNT_2: Arc<EntrySealedCommitted> = Arc::new(unsafe {
            entry_init!(
                ("class", Value::new_class("object")),
                ("name", Value::new_iname("test_account_1")),
                ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_2)),
                ("memberof", Value::new_refer(UUID_TEST_GROUP_2))
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
                    Value::new_uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    "acp_receiver_group",
                    Value::new_refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
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
                    Value::new_uuids("cc8e95b4-c24f-4d68-ba54-8bed76f63930").expect("uuid")
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
            let ac = AccessControls::new();
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
            let ac = AccessControls::new();
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

        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2.clone())];

        let se_a = unsafe {
            SearchEvent::new_impersonate_entry(
                E_TEST_ACCOUNT_1.clone(),
                filter_all!(f_pres("name")),
            )
        };
        let ex_a = vec![Arc::new(ev1.clone())];

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
        let _ = sketching::test_init();
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

        test_acp_search!(&se_rw, vec![acp.clone()], r_set.clone(), ex_some);
    }

    #[test]
    fn test_access_enforce_scope_search_attrs() {
        // Test that in ident only mode that all attrs are always denied. The op should already have
        // "nothing to do" based on search_filter_entries, but we do the "right thing" anyway.

        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1.clone())];

        let exv1 = unsafe { E_TESTPERSON_1_REDUCED.clone().into_sealed_committed() };

        let ex_anon_some = vec![exv1.clone()];
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
        let r_set = vec![Arc::new(ev1.clone())];

        let exv1 = unsafe { E_TESTPERSON_1_REDUCED.clone().into_sealed_committed() };
        let ex_anon = vec![exv1.clone()];

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

        let r_set = vec![Arc::new(ev1.clone())];

        let exv1 = unsafe { E_TESTPERSON_1_REDUCED.clone().into_sealed_committed() };
        let ex_anon = vec![exv1.clone()];

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
            let ac = AccessControls::new();
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
        let r_set = vec![Arc::new(ev1.clone())];

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
        test_acp_modify!(&me_purge_class, vec![acp_allow.clone()], &r_set, false);

        // Test reject pres class, but class not in classes
        test_acp_modify!(&me_pres_class, vec![acp_no_class.clone()], &r_set, false);
        // Test reject pres class, class in classes but not in pres attrs
        test_acp_modify!(&me_pres_class, vec![acp_deny.clone()], &r_set, false);
        // test reject rem class, but class not in classes
        test_acp_modify!(&me_rem_class, vec![acp_no_class.clone()], &r_set, false);
        // test reject rem class, class in classes but not in pres attrs
        test_acp_modify!(&me_rem_class, vec![acp_deny.clone()], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_modify() {
        let ev1 = unsafe { E_TESTPERSON_1.clone().into_sealed_committed() };
        let r_set = vec![Arc::new(ev1.clone())];

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

        test_acp_modify!(&me_pres_rw, vec![acp_allow.clone()], &r_set, true);
    }

    macro_rules! test_acp_create {
        (
            $ce:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::new();
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
            ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1.clone()];

        let ev2 = entry_init!(
            ("class", Value::new_class("account")),
            ("notallowed", Value::new_class("notallowed")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_1))
        );

        let r2_set = vec![ev2.clone()];

        let ev3 = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("notallowed")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_1))
        );
        let r3_set = vec![ev3.clone()];

        let ev4 = entry_init!(
            ("class", Value::new_class("account")),
            ("class", Value::new_class("group")),
            ("name", Value::new_iname("testperson1")),
            ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_1))
        );
        let r4_set = vec![ev4.clone()];

        // In this case, we can make the create event with an empty entry
        // set because we only reference the entries in r_set in the test.
        //
        // In the realy server code, the entry set is derived from and checked
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
            ("uuid", Value::new_uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1.clone()];

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
            Identity::from_impersonate_entry_readwrite(admin.clone()),
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
            let ac = AccessControls::new();
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
        let r_set = vec![Arc::new(ev1.clone())];

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
        let r_set = vec![Arc::new(ev1.clone())];

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
            Identity::from_impersonate_entry_readwrite(admin.clone()),
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
            let ac = AccessControls::new();
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
        let _ = sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_sealed_committed() };

        let r_set = vec![Arc::new(ev1.clone())];

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
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: btreeset![AttrString::from("name")],
                modify_pres: BTreeSet::new(),
                modify_rem: BTreeSet::new(),
                modify_class: BTreeSet::new(),
            }]
        )
    }

    #[test]
    fn test_access_effective_permission_check_2() {
        let _ = sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let e1: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(JSON_TESTPERSON1);
        let ev1 = unsafe { e1.into_sealed_committed() };

        let r_set = vec![Arc::new(ev1.clone())];

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
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: BTreeSet::new(),
                modify_pres: btreeset![AttrString::from("name")],
                modify_rem: btreeset![AttrString::from("name")],
                modify_class: btreeset![AttrString::from("object")],
            }]
        )
    }
}
