//! Contains structures related to the Identity that initiated an `Event` in the
//! server. Generally this Identity is what will have access controls applied to
//! and this provides the set of `Limits` to confine how many resources that the
//! identity may consume during operations to prevent denial-of-service.

use crate::be::Limits;
use std::collections::BTreeSet;
use std::hash::Hash;
use std::sync::Arc;
use uuid::uuid;

use kanidm_proto::v1::{ApiTokenPurpose, UatPurpose, UatPurposeStatus};

use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessScope {
    IdentityOnly,
    ReadOnly,
    ReadWrite,
    Synchronise,
}

impl std::fmt::Display for AccessScope {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AccessScope::IdentityOnly => write!(f, "identity only"),
            AccessScope::ReadOnly => write!(f, "read only"),
            AccessScope::ReadWrite => write!(f, "read write"),
            AccessScope::Synchronise => write!(f, "synchronise"),
        }
    }
}

impl From<&ApiTokenPurpose> for AccessScope {
    fn from(purpose: &ApiTokenPurpose) -> Self {
        match purpose {
            ApiTokenPurpose::ReadOnly => AccessScope::ReadOnly,
            ApiTokenPurpose::ReadWrite => AccessScope::ReadWrite,
            ApiTokenPurpose::Synchronise => AccessScope::Synchronise,
        }
    }
}

impl TryInto<ApiTokenPurpose> for AccessScope {
    type Error = OperationError;

    fn try_into(self: AccessScope) -> Result<ApiTokenPurpose, OperationError> {
        match self {
            AccessScope::ReadOnly => Ok(ApiTokenPurpose::ReadOnly),
            AccessScope::ReadWrite => Ok(ApiTokenPurpose::ReadWrite),
            AccessScope::Synchronise => Ok(ApiTokenPurpose::Synchronise),
            AccessScope::IdentityOnly => Err(OperationError::InvalidEntryState),
        }
    }
}

impl From<&UatPurpose> for AccessScope {
    fn from(purpose: &UatPurpose) -> Self {
        match purpose {
            UatPurpose::IdentityOnly => AccessScope::IdentityOnly,
            UatPurpose::ReadOnly => AccessScope::ReadOnly,
            UatPurpose::ReadWrite { .. } => AccessScope::ReadWrite,
        }
    }
}

impl TryInto<UatPurposeStatus> for AccessScope {
    type Error = OperationError;

    fn try_into(self: AccessScope) -> Result<UatPurposeStatus, OperationError> {
        match self {
            AccessScope::ReadOnly => Ok(UatPurposeStatus::ReadOnly),
            AccessScope::ReadWrite => Ok(UatPurposeStatus::ReadWrite),
            AccessScope::IdentityOnly => Ok(UatPurposeStatus::IdentityOnly),
            AccessScope::Synchronise => Err(OperationError::InvalidEntryState),
        }
    }
}

#[derive(Debug, Clone)]
/// Metadata and the entry of the current Identity which is an external account/user.
pub struct IdentUser {
    pub entry: Arc<Entry<EntrySealed, EntryCommitted>>,
    // IpAddr?
    // Other metadata?
}

#[derive(Debug, Clone)]
/// The type of Identity that is related to this session.
pub enum IdentType {
    User(IdentUser),
    Synch(Uuid),
    Internal,
}

#[derive(Debug, Clone, PartialEq, Hash, Ord, PartialOrd, Eq, Serialize, Deserialize)]
/// A unique identifier of this Identity, that can be associated to various
/// caching components.
pub enum IdentityId {
    // Time stamp of the originating event.
    // The uuid of the originiating user
    User(Uuid),
    Synch(Uuid),
    Internal,
}

impl From<&IdentType> for IdentityId {
    fn from(idt: &IdentType) -> Self {
        match idt {
            IdentType::Internal => IdentityId::Internal,
            IdentType::User(u) => IdentityId::User(u.entry.get_uuid()),
            IdentType::Synch(u) => IdentityId::Synch(*u),
        }
    }
}

#[derive(Debug, Clone)]
/// An identity that initiated an `Event`. Contains extra details about the session
/// and other info that can assist with server decision making.
pub struct Identity {
    pub origin: IdentType,
    // pub(crate) source:
    // pub(crate) impersonate: bool,
    // In a way I guess these are session claims?
    pub(crate) session_id: Uuid,
    pub(crate) scope: AccessScope,
    pub(crate) limits: Limits,
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.origin {
            IdentType::Internal => write!(f, "Internal ({})", self.scope),
            IdentType::Synch(u) => write!(f, "Synchronise ({}) ({})", u, self.scope),
            IdentType::User(u) => {
                let nv = u.entry.get_uuid2spn();
                write!(
                    f,
                    "User( {}, {} ) ({}, {})",
                    nv.to_proto_string_clone(),
                    u.entry.get_uuid().as_hyphenated(),
                    self.session_id,
                    self.scope
                )
            }
        }
    }
}

impl Identity {
    pub fn from_internal() -> Self {
        Identity {
            origin: IdentType::Internal,
            session_id: uuid!("00000000-0000-0000-0000-000000000000"),
            scope: AccessScope::ReadWrite,
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub fn from_impersonate_entry_identityonly(
        entry: Arc<Entry<EntrySealed, EntryCommitted>>,
    ) -> Self {
        Identity {
            origin: IdentType::User(IdentUser { entry }),
            session_id: uuid!("00000000-0000-0000-0000-000000000000"),
            scope: AccessScope::IdentityOnly,
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub fn from_impersonate_entry_readonly(entry: Arc<Entry<EntrySealed, EntryCommitted>>) -> Self {
        Identity {
            origin: IdentType::User(IdentUser { entry }),
            session_id: uuid!("00000000-0000-0000-0000-000000000000"),
            scope: AccessScope::ReadOnly,
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub fn from_impersonate_entry_readwrite(
        entry: Arc<Entry<EntrySealed, EntryCommitted>>,
    ) -> Self {
        Identity {
            origin: IdentType::User(IdentUser { entry }),
            session_id: uuid!("00000000-0000-0000-0000-000000000000"),
            scope: AccessScope::ReadWrite,
            limits: Limits::unlimited(),
        }
    }

    pub fn access_scope(&self) -> AccessScope {
        self.scope
    }

    pub fn get_session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn from_impersonate(ident: &Self) -> Self {
        // TODO #64 ?: In the future, we could change some of this data
        // to reflect the fact we are infact impersonating the action
        // rather than the user explicitly requesting it. Could matter
        // to audits and logs to determine what happened.
        ident.clone()
    }

    pub fn is_internal(&self) -> bool {
        matches!(self.origin, IdentType::Internal)
    }

    pub fn get_uuid(&self) -> Option<Uuid> {
        match &self.origin {
            IdentType::Internal => None,
            IdentType::User(u) => Some(u.entry.get_uuid()),
            IdentType::Synch(u) => Some(*u),
        }
    }

    pub fn get_event_origin_id(&self) -> IdentityId {
        IdentityId::from(&self.origin)
    }

    #[cfg(test)]
    pub fn has_claim(&self, claim: &str) -> bool {
        match &self.origin {
            IdentType::Internal | IdentType::Synch(_) => false,
            IdentType::User(u) => u
                .entry
                .attribute_equality("claim", &PartialValue::new_iutf8(claim)),
        }
    }

    pub fn is_memberof(&self, group: Uuid) -> bool {
        match &self.origin {
            IdentType::Internal | IdentType::Synch(_) => false,
            IdentType::User(u) => u
                .entry
                .attribute_equality("memberof", &PartialValue::Refer(group)),
        }
    }

    pub fn get_memberof(&self) -> Option<&BTreeSet<Uuid>> {
        match &self.origin {
            IdentType::Internal | IdentType::Synch(_) => None,
            IdentType::User(u) => u.entry.get_ava_refer("memberof"),
        }
    }

    pub fn get_oauth2_consent_scopes(&self, oauth2_rs: Uuid) -> Option<&BTreeSet<String>> {
        match &self.origin {
            IdentType::Internal | IdentType::Synch(_) => None,
            IdentType::User(u) => u
                .entry
                .get_ava_as_oauthscopemaps("oauth2_consent_scope_map")
                .and_then(|scope_map| scope_map.get(&oauth2_rs)),
        }
    }
}
