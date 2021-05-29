pub(crate) mod account;
pub(crate) mod authsession;
pub(crate) mod delayed;
pub(crate) mod event;
pub(crate) mod group;
pub(crate) mod mfareg;
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
