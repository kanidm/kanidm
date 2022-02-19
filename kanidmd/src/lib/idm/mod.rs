//! The Identity Management components that are layered ontop of the [QueryServer](crate::server::QueryServer). These allow
//! rich and expressive events and transformations that are lowered into the correct/relevant
//! actions in the [QueryServer](crate::server::QueryServer). Generally this is where "Identity Management" policy and code
//! is implemented.

pub(crate) mod account;
pub(crate) mod authsession;
pub(crate) mod delayed;
pub(crate) mod event;
pub(crate) mod group;
pub(crate) mod mfareg;
pub mod oauth2;
pub(crate) mod radius;
pub mod server;
pub(crate) mod unix;

use kanidm_proto::v1::{AuthAllowed, AuthMech};

#[derive(Debug)]
pub enum AuthState {
    Choose(Vec<AuthMech>),
    Continue(Vec<AuthAllowed>),
    Denied(String),
    Success(String),
}
