use super::AccessResult;
use crate::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::filter::{Filter, FilterValid, FilterValidResolved};

use kanidm_proto::v1::Filter as ProtoFilter;

// =========================================================================
// PARSE ENTRY TO ACP, AND ACP MANAGEMENT
// =========================================================================

#[derive(Debug, Clone)]
pub struct AccessControlSearch {
    pub acp: AccessControlProfile,
    pub attrs: BTreeSet<AttrString>,
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
    pub(super) unsafe fn from_raw(
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

pub(super) fn search_filter_entries<'a>(
    se: &SearchEvent,
    related_acp: &'a [(&AccessControlSearch, Filter<FilterValidResolved>)],
    entry: &'a Arc<EntrySealedCommitted>,
) -> AccessResult<'a> {
    // If this is an internal search, return our working set.
    match &se.ident.origin {
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
    info!(event = %se.ident, "Access check for search (filter) event");

    match se.ident.access_scope() {
        AccessScope::IdentityOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to search");
            return AccessResult::Denied;
        }
        AccessScope::ReadOnly | AccessScope::ReadWrite => {
            // As you were
        }
    };

    let allowed_attrs: BTreeSet<&str> = related_acp
        .iter()
        .filter_map(|(acs, f_res)| {
            // if it applies
            if entry.entry_match_no_index(f_res) {
                security_access!(entry = ?entry.get_uuid(), acs = %acs.acp.name, "entry matches acs");
                // add search_attrs to allowed.
                Some(acs.attrs.iter().map(|s| s.as_str()))
            } else {
                // should this be `security_access`?
                trace!(entry = ?entry.get_uuid(), acs = %acs.acp.name, "entry DOES NOT match acs");
                None
            }
        })
        .flatten()
        .collect();

    AccessResult::Allow(allowed_attrs)
}

pub(super) fn search_filter_entry_attributes<'a>(
    se: &SearchEvent,
    related_acp: &'a [(&AccessControlSearch, Filter<FilterValidResolved>)],
    entry: &'a Arc<EntrySealedCommitted>,
) -> AccessResult<'a> {
    // If this is an internal search, do nothing. This can occur in some test cases ONLY
    match &se.ident.origin {
        IdentType::Internal => {
            if cfg!(test) {
                trace!(
                    "TEST: Internal search in external interface - allowing due to cfg test ..."
                );
                return AccessResult::Grant;
            } else {
                // In production we can't risk leaking data here, so we return
                // empty sets.
                security_critical!("IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                // No need to check ACS
                return AccessResult::Denied;
            }
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return AccessResult::Denied;
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

    // Get the set of attributes you can see for this entry
    // this is within your related acp scope.
    let allowed_attrs: BTreeSet<&str> = related_acp
        .iter()
        .filter_map(|(acs, f_res)| {
            if entry.entry_match_no_index(f_res) {
                security_access!(
                    target = ?entry.get_uuid(),
                    acs = %acs.acp.name,
                    "target entry matches acs",
                );
                Some(acs.attrs.iter().map(|s| s.as_str()))
            } else {
                trace!(
                    target = ?entry.get_uuid(),
                    acs = %acs.acp.name,
                    "target entry DOES NOT match acs",
                );
                None
            }
        })
        .flatten()
        .collect();

    AccessResult::Allow(allowed_attrs)
}

#[derive(Debug, Clone)]
pub struct AccessControlDelete {
    pub acp: AccessControlProfile,
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
    pub(super) unsafe fn from_raw(
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
    pub acp: AccessControlProfile,
    pub classes: Vec<AttrString>,
    pub attrs: Vec<AttrString>,
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
    pub(super) unsafe fn from_raw(
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
    pub acp: AccessControlProfile,
    pub classes: Vec<AttrString>,
    pub presattrs: Vec<AttrString>,
    pub remattrs: Vec<AttrString>,
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
    pub(super) unsafe fn from_raw(
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
pub struct AccessControlProfile {
    pub name: String,
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
    pub receiver: Option<Uuid>,
    // or
    //  Filter
    //  Group
    //  Self
    // and
    //  exclude
    //    Group
    pub targetscope: Filter<FilterValid>,
}

impl AccessControlProfile {
    pub(super) fn try_from(
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
