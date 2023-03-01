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

use clap::Parser;
use futures::executor::block_on;
use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

include!("./opt/ssh_authorizedkeys.rs");

#[tokio::main]
async fn main() {
    let opt = SshAuthorizedOpt::parse();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    if opt.version {
        println!(
            "{}",
            kanidm_proto::utils::get_version("kanidm_ssh_authorizedkeys")
        );
        std::process::exit(0);
    }
    sketching::tracing_subscriber::fmt::init();

    debug!("Starting authorized keys tool ...");

    let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH)
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse {}: {:?}", DEFAULT_CONFIG_PATH, e);
            std::process::exit(1);
        }
    };

    debug!(
        "Using kanidm_unixd socket path: {:?}",
        cfg.sock_path.as_str()
    );

    // see if the kanidm_unixd socket exists and quit if not
    if !PathBuf::from(&cfg.sock_path).exists() {
        error!(
            "Failed to find unix socket at {}, quitting!",
            cfg.sock_path.as_str()
        );
        std::process::exit(1);
    }
    let req = ClientRequest::SshKey(opt.account_id);

    match block_on(call_daemon(cfg.sock_path.as_str(), req)) {
        Ok(r) => match r {
            ClientResponse::SshKeys(sk) => sk.iter().for_each(|k| {
                println!("{}", k);
            }),
            _ => {
                error!("Error calling kanidm_unixd: unexpected response -> {:?}", r);
            }
        },
        Err(e) => {
            error!("Error calling kanidm_unixd -> {:?}", e);
        }
    }
}
