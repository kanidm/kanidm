#![feature(try_from)]

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate r2d2;
extern crate r2d2_sqlite;
extern crate rusqlite;
extern crate uuid;

extern crate bytes;
extern crate chrono;
extern crate env_logger;

extern crate regex;
#[macro_use]
extern crate lazy_static;

extern crate concread;

// use actix::prelude::*;
// use actix_web::{
//    http, middleware, App, AsyncResponder, FutureResponse, HttpRequest, HttpResponse, Path, State,
// };

// use futures::Future;

// This has to be before be so the import order works
#[macro_use]
mod log;
#[macro_use]
mod audit;
mod be;
mod constants;
mod entry;
mod event;
mod identity;
mod plugins;
mod schema;
mod server;

pub mod config;
pub mod core;
pub mod error;
pub mod filter;
pub mod proto_v1;
