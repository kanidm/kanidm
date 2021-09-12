//! The Kanidmd server library. This implements all of the internal components of the server
//! which is used to process authentication, store identities and enforce access controls.

#![recursion_limit = "512"]
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
// #![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(all(jemallocator, test))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rusqlite;

#[macro_use]
extern crate lazy_static;

// This has to be before 'be' so the import order works
#[macro_use]
pub mod macros;

mod crypto;
pub mod utils;
#[macro_use]
mod async_log;
#[macro_use]
pub mod audit;
pub mod be;
pub mod constants;
pub mod credential;
pub mod entry;
pub mod event;
pub mod filter;
pub mod identity;
mod interval;
pub(crate) mod ldap;
mod modify;
pub mod value;
pub mod valueset;
#[macro_use]
mod plugins;
mod access;
mod actors;
pub mod idm;
mod repl;
mod schema;
pub mod server;
mod status;

pub mod config;
pub mod core;

/// A prelude of imports that should be imported by all other Kanidm modules to
/// help make imports cleaner.
pub mod prelude {
    pub use crate::utils::duration_from_epoch_now;
    pub use kanidm_proto::v1::OperationError;
    pub use smartstring::alias::String as AttrString;
    pub use url::Url;
    pub use uuid::Uuid;

    pub use crate::audit::AuditScope;
    pub use crate::constants::*;
    pub use crate::filter::{Filter, FilterInvalid};

    pub use crate::entry::{
        Entry, EntryCommitted, EntryInit, EntryInvalid, EntryInvalidCommitted, EntryNew,
        EntryReduced, EntrySealed, EntrySealedCommitted, EntryTuple, EntryValid,
    };
    pub use crate::identity::Identity;
    pub use crate::server::{
        QueryServer, QueryServerReadTransaction, QueryServerTransaction,
        QueryServerWriteTransaction,
    };
    pub use crate::value::{IndexType, PartialValue, SyntaxType, Value};
    pub use crate::valueset::ValueSet;
    pub use crate::{
        admin_error, admin_info, admin_warn, filter_error, filter_info, filter_trace, filter_warn,
        perf_trace, request_error, request_info, request_trace, request_warn, security_access,
        security_critical, security_info, spanned,
    };
}

pub mod tracing_tree;
