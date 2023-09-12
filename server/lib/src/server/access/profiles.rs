use crate::prelude::*;
use std::collections::BTreeSet;

use crate::filter::{Filter, FilterValid};

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
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlSearch.into()) {
            admin_error!("class {} not present.", EntryClass::AccessControlSearch);
            return Err(OperationError::InvalidAcpState(format!(
                "Missing {}",
                EntryClass::AccessControlSearch
            )));
        }

        let attrs = value
            .get_ava_iter_iutf8(Attribute::AcpSearchAttr)
            .ok_or_else(|| {
                admin_error!("Missing {}", Attribute::AcpSearchAttr);
                OperationError::InvalidAcpState(format!("Missing {}", Attribute::AcpSearchAttr))
            })?
            .map(AttrString::from)
            .collect();

        let acp = AccessControlProfile::try_from(qs, value)?;

        Ok(AccessControlSearch { acp, attrs })
    }

    /// ⚠️  - Manually create a search access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
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
            attrs: attrs.split_whitespace().map(AttrString::from).collect(),
        }
    }
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
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlDelete.into()) {
            admin_error!("class access_control_delete not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_delete".to_string(),
            ));
        }

        Ok(AccessControlDelete {
            acp: AccessControlProfile::try_from(qs, value)?,
        })
    }

    /// ⚠️  - Manually create a delete access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
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
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlCreate.into()) {
            admin_error!("class {} not present.", EntryClass::AccessControlCreate);
            return Err(OperationError::InvalidAcpState(format!(
                "Missing {}",
                EntryClass::AccessControlCreate
            )));
        }

        let attrs = value
            .get_ava_iter_iutf8(Attribute::AcpCreateAttr)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let classes = value
            .get_ava_iter_iutf8(Attribute::AcpCreateClass)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        Ok(AccessControlCreate {
            acp: AccessControlProfile::try_from(qs, value)?,
            classes,
            attrs,
        })
    }

    /// ⚠️  - Manually create a create access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
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
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlModify.into()) {
            admin_error!("class access_control_modify not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_modify".to_string(),
            ));
        }

        let presattrs = value
            .get_ava_iter_iutf8(Attribute::AcpModifyPresentAttr)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let remattrs = value
            .get_ava_iter_iutf8(Attribute::AcpModifyRemovedAttr)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        let classes = value
            .get_ava_iter_iutf8(Attribute::AcpModifyClass)
            .map(|i| i.map(AttrString::from).collect())
            .unwrap_or_else(Vec::new);

        Ok(AccessControlModify {
            acp: AccessControlProfile::try_from(qs, value)?,
            classes,
            presattrs,
            remattrs,
        })
    }

    /// ⚠️  - Manually create a modify access profile from values.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(super) fn from_raw(
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
            classes: classes.split_whitespace().map(AttrString::from).collect(),
            presattrs: presattrs.split_whitespace().map(AttrString::from).collect(),
            remattrs: remattrs.split_whitespace().map(AttrString::from).collect(),
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
        if !value.attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into()) {
            admin_error!("class access_control_profile not present.");
            return Err(OperationError::InvalidAcpState(
                "Missing access_control_profile".to_string(),
            ));
        }

        // copy name
        let name = value
            .get_ava_single_iname(Attribute::Name)
            .ok_or_else(|| {
                admin_error!("Missing {}", Attribute::Name);
                OperationError::InvalidAcpState(format!("Missing {}", Attribute::Name))
            })?
            .to_string();
        // copy uuid
        let uuid = value.get_uuid();
        // receiver, and turn to real filter

        // === ⚠️   WARNING!!! ⚠️  ===
        // See struct ACP for details.
        let receiver = value.get_ava_single_refer(Attribute::AcpReceiverGroup);
        /*
        .ok_or_else(|| {
            admin_error!("Missing acp_receiver_group");
            OperationError::InvalidAcpState("Missing acp_receiver_group".to_string())
        })?;
        */

        // targetscope, and turn to real filter
        let targetscope_f: ProtoFilter = value
            .get_ava_single_protofilter(Attribute::AcpTargetScope)
            // .map(|pf| pf.clone())
            .cloned()
            .ok_or_else(|| {
                admin_error!("Missing {}", Attribute::AcpTargetScope);
                OperationError::InvalidAcpState(format!("Missing {}", Attribute::AcpTargetScope))
            })?;

        let ident = Identity::from_internal();

        let targetscope_i = Filter::from_rw(&ident, &targetscope_f, qs).map_err(|e| {
            admin_error!("{} validation failed {:?}", Attribute::AcpTargetScope, e);
            e
        })?;

        let targetscope = targetscope_i.validate(qs.get_schema()).map_err(|e| {
            admin_error!("{} Schema Violation {:?}", Attribute::AcpTargetScope, e);
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
