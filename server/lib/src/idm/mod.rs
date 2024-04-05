//! The Identity Management components that are layered on top of the [QueryServer](crate::server::QueryServer). These allow
//! rich and expressive events and transformations that are lowered into the correct/relevant
//! actions in the [QueryServer](crate::server::QueryServer). Generally this is where "Identity Management" policy and code
//! is implemented.

pub mod account;
pub(crate) mod accountpolicy;
pub(crate) mod applinks;
pub mod audit;
pub(crate) mod authsession;
pub mod credupdatesession;
pub mod delayed;
pub mod event;
pub mod group;
pub mod identityverification;
pub mod ldap;
pub mod oauth2;
pub(crate) mod radius;
pub(crate) mod reauth;
pub mod scim;
pub mod server;
pub mod serviceaccount;
pub(crate) mod unix;

use crate::server::identity::Source;
use compact_jwt::JwsCompact;
use kanidm_proto::v1::{AuthAllowed, AuthIssueSession, AuthMech};
use std::fmt;

pub enum AuthState {
    Choose(Vec<AuthMech>),
    Continue(Vec<AuthAllowed>),
    Denied(String),
    Success(JwsCompact, AuthIssueSession),
}

impl fmt::Debug for AuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthState::Choose(mechs) => write!(f, "AuthState::Choose({mechs:?})"),
            AuthState::Continue(allow) => write!(f, "AuthState::Continue({allow:?})"),
            AuthState::Denied(reason) => write!(f, "AuthState::Denied({reason:?})"),
            AuthState::Success(_token, issue) => write!(f, "AuthState::Success({issue:?})"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientAuthInfo {
    pub source: Source,
    pub client_cert: Option<ClientCertInfo>,
    pub bearer_token: Option<JwsCompact>,
}

#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    pub subject_key_id: Option<Vec<u8>>,
    pub cn: Option<String>,
}

#[cfg(test)]
impl From<Source> for ClientAuthInfo {
    fn from(value: Source) -> ClientAuthInfo {
        ClientAuthInfo {
            source: value,
            client_cert: None,
            bearer_token: None,
        }
    }
}

#[cfg(test)]
impl From<JwsCompact> for ClientAuthInfo {
    fn from(value: JwsCompact) -> ClientAuthInfo {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: None,
            bearer_token: Some(value),
        }
    }
}

#[cfg(test)]
impl From<ClientCertInfo> for ClientAuthInfo {
    fn from(value: ClientCertInfo) -> ClientAuthInfo {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: Some(value),
            bearer_token: None,
        }
    }
}
