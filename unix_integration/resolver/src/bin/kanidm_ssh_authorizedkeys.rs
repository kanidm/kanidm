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
use std::process::ExitCode;

use clap::Parser;
use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

include!("../opt/ssh_authorizedkeys.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = SshAuthorizedOpt::parse();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    if opt.version {
        println!("ssh_authorizedkeys {}", env!("KANIDM_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    sketching::tracing_subscriber::fmt::init();

    if opt.account_id.is_none() {
        error!("No account specified, quitting!");
        return ExitCode::FAILURE;
    }

    debug!("Starting authorized keys tool ...");

    let cfg = match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH)
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse {}: {:?}", DEFAULT_CONFIG_PATH, e);
            return ExitCode::FAILURE;
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
        return ExitCode::FAILURE;
    }
    // safe because we've already thrown an error if it's not there
    let req = ClientRequest::SshKey(opt.account_id.unwrap_or("".to_string()));

    match call_daemon(cfg.sock_path.as_str(), req, cfg.unix_sock_timeout).await {
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
    };
    ExitCode::SUCCESS
}
