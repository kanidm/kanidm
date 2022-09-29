//! The Identity Management components that are layered ontop of the [QueryServer](crate::server::QueryServer). These allow
//! rich and expressive events and transformations that are lowered into the correct/relevant
//! actions in the [QueryServer](crate::server::QueryServer). Generally this is where "Identity Management" policy and code
//! is implemented.

pub(crate) mod account;
pub(crate) mod authsession;
pub(crate) mod credupdatesession;
pub(crate) mod delayed;
pub(crate) mod event;
pub(crate) mod group;
pub mod oauth2;
pub(crate) mod radius;
pub mod server;
pub(crate) mod serviceaccount;
pub(crate) mod unix;

use std::fmt;

use kanidm_proto::v1::{AuthAllowed, AuthMech};

pub enum AuthState {
    Choose(Vec<AuthMech>),
    Continue(Vec<AuthAllowed>),
    Denied(String),
    Success(String),
}

impl fmt::Debug for AuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthState::Choose(mechs) => write!(f, "AuthState::Choose({:?})", mechs),
            AuthState::Continue(allow) => write!(f, "AuthState::Continue({:?})", allow),
            AuthState::Denied(reason) => write!(f, "AuthState::Denied({:?})", reason),
            AuthState::Success(_token) => write!(f, "AuthState::Success"),
        }
    }
}
