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
extern crate log;

use log::debug;
use structopt::StructOpt;

use futures::executor::block_on;

use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

include!("./opt/ssh_authorizedkeys.rs");

#[tokio::main]
async fn main() {
    let opt = SshAuthorizedOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    debug!("Starting authorized keys tool ...");

    let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config("/etc/kanidm/unixd")
    {
        Ok(c) => c,
        Err(_e) => {
            error!("Failed to parse /etc/kanidm/unixd");
            std::process::exit(1);
        }
    };

    let req = ClientRequest::SshKey(opt.account_id);

    match block_on(call_daemon(cfg.sock_path.as_str(), req)) {
        Ok(r) => match r {
            ClientResponse::SshKeys(sk) => sk.iter().for_each(|k| {
                println!("{}", k);
            }),
            _ => {
                error!("Error: unexpected response -> {:?}", r);
            }
        },
        Err(e) => {
            error!("Error -> {:?}", e);
        }
    }
}
