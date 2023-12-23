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

use std::fmt;

use kanidm_proto::v1::{AuthAllowed, AuthIssueSession, AuthMech};

pub enum AuthState {
    Choose(Vec<AuthMech>),
    Continue(Vec<AuthAllowed>),
    Denied(String),
    Success(String, AuthIssueSession),
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
    pub ip_addr: IpAddr,
    pub client_cert: Option<ClientCertInfo>,
    pub bearer_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    pub subject_key_id: Option<Vec<u8>>,
    pub cn: Option<String>,
}
