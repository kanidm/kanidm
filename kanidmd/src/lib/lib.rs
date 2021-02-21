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
mod filter;
mod interval;
pub(crate) mod ldap;
mod modify;
pub mod value;
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
