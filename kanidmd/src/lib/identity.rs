//! Contains structures related to the Identity that initiated an `Event` in the
//! server. Generally this Identity is what will have access controls applied to
//! and this provides the set of `Limits` to confine how many resources that the
//! identity may consume during operations to prevent denial-of-service.

use crate::prelude::*;
use kanidm_proto::v1::UserAuthToken;
use std::hash::Hash;
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Limits on the resources a single event can consume. These are defined per-event
/// as they are derived from the userAuthToken based on that individual session
pub struct Limits {
    pub unindexed_allow: bool,
    pub search_max_results: usize,
    pub search_max_filter_test: usize,
    pub filter_max_elements: usize,
}

impl Limits {
    pub fn unlimited() -> Self {
        Limits {
            unindexed_allow: true,
            search_max_results: usize::MAX,
            search_max_filter_test: usize::MAX,
            filter_max_elements: usize::MAX,
        }
    }

    // From a userauthtoken
    pub fn from_uat(uat: &UserAuthToken) -> Self {
        Limits {
            unindexed_allow: uat.lim_uidx,
            search_max_results: uat.lim_rmax,
            search_max_filter_test: uat.lim_pmax,
            filter_max_elements: uat.lim_fmax,
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
    Internal,
}

#[derive(Debug, Clone, PartialEq, Hash, Ord, PartialOrd, Eq, Serialize, Deserialize)]
/// A unique identifier of this Identity, that can be associated to various
/// caching components.
pub enum IdentityId {
    // Time stamp of the originating event.
    // The uuid of the originiating user
    User(Uuid),
    Internal,
}

impl From<&IdentType> for IdentityId {
    fn from(idt: &IdentType) -> Self {
        match idt {
            IdentType::Internal => IdentityId::Internal,
            IdentType::User(u) => IdentityId::User(*u.entry.get_uuid()),
        }
    }
}

#[derive(Debug, Clone)]
/// An identity that initiated an `Event`.
pub struct Identity {
    pub origin: IdentType,
    pub(crate) limits: Limits,
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.origin {
            IdentType::Internal => write!(f, "Internal"),
            IdentType::User(u) => {
                let nv = u.entry.get_uuid2spn();
                write!(
                    f,
                    "User( {}, {} ) ",
                    nv.to_proto_string_clone(),
                    u.entry.get_uuid().to_hyphenated_ref()
                )
            }
        }
    }
}

impl Identity {
    pub fn from_internal() -> Self {
        Identity {
            origin: IdentType::Internal,
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub fn from_impersonate_entry(entry: Arc<Entry<EntrySealed, EntryCommitted>>) -> Self {
        Identity {
            origin: IdentType::User(IdentUser { entry }),
            limits: Limits::unlimited(),
        }
    }

    #[cfg(test)]
    pub unsafe fn from_impersonate_entry_ser(e: &str) -> Self {
        let ei: Entry<EntryInit, EntryNew> = Entry::unsafe_from_entry_str(e);
        Self::from_impersonate_entry(Arc::new(ei.into_sealed_committed()))
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
            IdentType::User(u) => Some(*u.entry.get_uuid()),
        }
    }

    pub fn get_event_origin_id(&self) -> IdentityId {
        IdentityId::from(&self.origin)
    }

    #[cfg(test)]
    pub fn has_claim(&self, claim: &str) -> bool {
        match &self.origin {
            IdentType::Internal => false,
            IdentType::User(u) => u
                .entry
                .attribute_equality("claim", &PartialValue::new_iutf8(claim)),
        }
    }

    pub fn is_memberof(&self, group: Uuid) -> bool {
        match &self.origin {
            IdentType::Internal => false,
            IdentType::User(u) => u
                .entry
                .attribute_equality("memberof", &PartialValue::new_refer(group)),
        }
    }
}
