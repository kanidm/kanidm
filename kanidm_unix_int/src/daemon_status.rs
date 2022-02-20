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

#[macro_use]
extern crate tracing;

use std::path::PathBuf;
use structopt::StructOpt;

// use futures::executor::block_on;

use kanidm_unix_common::client_sync::call_daemon_blocking;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

include!("./opt/unixd_status.rs");

fn main() {
    let opt = UnixdStatusOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    tracing_subscriber::fmt::init();

    trace!("Starting cache status tool ...");

    let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config("/etc/kanidm/unixd")
    {
        Ok(c) => c,
        Err(_e) => {
            error!("Failed to parse /etc/kanidm/unixd");
            std::process::exit(1);
        }
    };

    let req = ClientRequest::Status;

    let spath = PathBuf::from(cfg.sock_path.as_str());
    if !spath.exists() {
        error!(
            "kanidm_unixd socket {} does not exist - is the service running?",
            cfg.sock_path
        )
    } else {
        match call_daemon_blocking(cfg.sock_path.as_str(), &req) {
            Ok(r) => match r {
                ClientResponse::Ok => println!("working!"),
                _ => {
                    error!("Error: unexpected response -> {:?}", r);
                }
            },
            Err(e) => {
                error!("Error -> {:?}", e);
            }
        }
    }
}
