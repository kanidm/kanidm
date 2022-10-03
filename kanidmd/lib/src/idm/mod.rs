//! The Identity Management components that are layered ontop of the [QueryServer](crate::server::QueryServer). These allow
//! rich and expressive events and transformations that are lowered into the correct/relevant
//! actions in the [QueryServer](crate::server::QueryServer). Generally this is where "Identity Management" policy and code
//! is implemented.

pub mod account;
pub mod authsession;
pub mod credupdatesession;
pub mod delayed;
pub mod event;
pub mod group;
pub mod oauth2;
pub mod radius;
pub mod server;
pub mod serviceaccount;
pub mod unix;

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
