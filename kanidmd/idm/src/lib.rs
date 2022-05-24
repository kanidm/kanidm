//! The Kanidmd server library. This implements all of the internal components of the server
//! which is used to process authentication, store identities and enforce access controls.

#![recursion_limit = "512"]
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(all(jemallocator, test))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate rusqlite;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate lazy_static;

// This has to be before 'be' so the import order works
#[macro_use]
pub mod macros;

pub mod crypto;
pub mod utils;
#[macro_use]
pub mod audit;
pub mod be;
pub mod constants;
pub mod credential;
pub mod entry;
pub mod event;
pub mod filter;
pub mod identity;
pub mod interval;
pub mod ldap;
mod modify;
pub mod value;
pub mod valueset;
#[macro_use]
mod plugins;
mod access;
pub mod actors;
pub mod idm;
mod repl;
pub mod schema;
pub mod server;
pub mod status;

pub mod config;

/// A prelude of imports that should be imported by all other Kanidm modules to
/// help make imports cleaner.
pub mod prelude {
    pub use crate::utils::duration_from_epoch_now;
    pub use kanidm_proto::v1::OperationError;
    pub use smartstring::alias::String as AttrString;
    pub use url::Url;
    pub use uuid::Uuid;

    pub use crate::tagged_event;
    pub use crate::tracing_tree::EventTag;

    pub use crate::constants::*;
    pub use crate::filter::{
        f_and, f_andnot, f_eq, f_id, f_inc, f_lt, f_or, f_pres, f_self, f_spn_name, f_sub,
    };
    pub use crate::filter::{Filter, FilterInvalid, FC};
    pub use crate::modify::{m_pres, m_purge, m_remove};
    pub use crate::modify::{Modify, ModifyList};

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
    pub use crate::valueset::{
        ValueSet, ValueSetBool, ValueSetCid, ValueSetIndex, ValueSetIutf8, ValueSetRefer,
        ValueSetSecret, ValueSetSpn, ValueSetSyntax, ValueSetT, ValueSetUint32, ValueSetUtf8,
        ValueSetUuid,
    };
    pub use crate::{
        admin_error, admin_info, admin_warn, filter_error, filter_info, filter_trace, filter_warn,
        perf_trace, request_error, request_info, request_trace, request_warn, security_access,
        security_critical, security_error, security_info, spanned,
    };
}

pub mod tracing_tree;
