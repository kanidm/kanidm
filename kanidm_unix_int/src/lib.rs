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

#[cfg(target_family = "unix")]
#[macro_use]
extern crate tracing;
#[cfg(target_family = "unix")]
#[macro_use]
extern crate rusqlite;

#[cfg(target_family = "unix")]
pub mod cache;
#[cfg(target_family = "unix")]
pub mod client;
#[cfg(target_family = "unix")]
pub mod client_sync;
#[cfg(target_family = "unix")]
pub mod constants;
#[cfg(target_family = "unix")]
pub(crate) mod db;
#[cfg(target_family = "unix")]
pub mod unix_config;
#[cfg(target_family = "unix")]
pub mod unix_proto;
