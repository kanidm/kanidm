//! The Kanidmd server library. This implements all of the internal components of the server
//! which is used to process authentication, store identities and enforce access controls.

#![deny(warnings)]
#![recursion_limit = "512"]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::unreachable)]

#[cfg(all(jemallocator, test, not(target_family = "windows")))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate rusqlite;
#[macro_use]
extern crate tracing;
#[macro_use]
extern crate lazy_static;

// #[macro_use]
// extern crate sketching;

// This has to be before 'be' so the import order works
#[macro_use]
pub mod macros;

pub mod be;
pub mod constants;
pub mod credential;
pub mod entry;
pub mod event;
pub mod filter;
pub mod identity;
pub mod ldap;
pub mod modify;
pub mod utils;
pub mod value;
pub mod valueset;
#[macro_use]
mod plugins;
mod access;
pub mod idm;
mod repl;
pub mod schema;
pub mod server;
pub mod status;
#[cfg(test)]
mod testkit;

/// A prelude of imports that should be imported by all other Kanidm modules to
/// help make imports cleaner.
pub mod prelude {
    pub use kanidm_proto::v1::{ConsistencyError, OperationError};
    pub use sketching::{
        admin_debug, admin_error, admin_info, admin_warn, filter_error, filter_info, filter_trace,
        filter_warn, perf_trace, request_error, request_info, request_trace, request_warn,
        security_access, security_critical, security_error, security_info, tagged_event, EventTag,
    };
    pub use smartstring::alias::String as AttrString;
    pub use url::Url;
    pub use uuid::Uuid;

    pub use crate::constants::*;
    pub use crate::entry::{
        Entry, EntryCommitted, EntryInit, EntryInitNew, EntryInvalid, EntryInvalidCommitted,
        EntryNew, EntryReduced, EntryReducedCommitted, EntrySealed, EntrySealedCommitted,
        EntryTuple, EntryValid,
    };
    pub use crate::filter::{
        f_and, f_andnot, f_eq, f_id, f_inc, f_lt, f_or, f_pres, f_self, f_spn_name, f_sub, Filter,
        FilterInvalid, FC,
    };
    pub use crate::identity::{AccessScope, IdentType, Identity};
    pub use crate::modify::{m_pres, m_purge, m_remove, Modify, ModifyInvalid, ModifyList};
    pub use crate::server::{
        QueryServer, QueryServerReadTransaction, QueryServerTransaction,
        QueryServerWriteTransaction,
    };
    pub use crate::utils::duration_from_epoch_now;
    pub use crate::value::{IndexType, PartialValue, SyntaxType, Value};
    pub use crate::valueset::{
        ValueSet, ValueSetBool, ValueSetCid, ValueSetIndex, ValueSetIutf8, ValueSetRefer,
        ValueSetSecret, ValueSetSpn, ValueSetSyntax, ValueSetT, ValueSetUint32, ValueSetUtf8,
        ValueSetUuid,
    };

    #[cfg(test)]
    pub use kanidmd_lib_macros::*;
}
