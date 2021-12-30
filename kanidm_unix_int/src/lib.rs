#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate rusqlite;

pub mod cache;
pub mod client;
pub mod client_sync;
pub mod constants;
pub(crate) mod db;
pub mod unix_config;
pub mod unix_proto;
