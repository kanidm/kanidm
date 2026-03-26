//! A FreeRADIUS module for Kanidm authentication and authorization.
//!
//! Here be unsafe dragons.

#![deny(warnings)]
#![deny(deprecated)]
#![recursion_limit = "512"]
#![warn(unused_extern_crates)]
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![deny(clippy::indexing_slicing)]
#![allow(clippy::unreachable)]

#[cfg(feature = "extern-freeradius-module")]
pub mod ffi;
#[cfg(feature = "extern-freeradius-module")]
mod freeradius;

#[cfg(feature = "extern-freeradius-module")]
mod glue;

#[cfg(any(test, feature = "extern-freeradius-module"))]
pub(crate) mod error;
#[cfg(any(test, feature = "extern-freeradius-module"))]
pub(crate) mod logic;
