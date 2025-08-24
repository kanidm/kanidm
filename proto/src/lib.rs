//! Kanidm JSON protocol definitions
//!
//! This library defines the elements that are used by Kanidm's http APIs.
//! Each module has different support levels which define the projects policy
//! on change for the module.

#![deny(warnings)]
#![warn(unused_extern_crates)]
// #![warn(missing_docs)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

pub mod cli;
pub mod constants;
pub mod internal;
pub mod messages;
pub mod oauth2;
pub mod scim_v1;
pub mod v1;

pub mod attribute;

pub use webauthn_rs_proto as webauthn;
