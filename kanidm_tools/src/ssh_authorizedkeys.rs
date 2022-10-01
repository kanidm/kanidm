#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::path::PathBuf;

use clap::Parser;
use kanidm_client::{ClientError, KanidmClientBuilder};
use kanidm_proto::constants::{DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH_HOME};
use tracing::{debug, error};

include!("opt/ssh_authorizedkeys.rs");

// For now we lift a few things from the main.rs to use.
//
// usage: AuthorizedKeysCommand /usr/sbin/kanidm_ssh_authorizedkeys %u -H URL -D anonymous -C /etc/kanidm/ca.pem
//
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = SshAuthorizedOpt::parse();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    tracing_subscriber::fmt::init();

    let config_path: String = shellexpand::tilde(DEFAULT_CLIENT_CONFIG_PATH_HOME).into_owned();
    debug!("Attempting to use config {}", DEFAULT_CLIENT_CONFIG_PATH);
    let client_builder = KanidmClientBuilder::new()
        .read_options_from_optional_config(DEFAULT_CLIENT_CONFIG_PATH)
        .and_then(|cb| {
            debug!("Attempting to use config {}", config_path);
            cb.read_options_from_optional_config(config_path)
        })
        .unwrap_or_else(|e| {
            error!("Failed to parse config (if present) -- {:?}", e);
            std::process::exit(1);
        });

    let client_builder = match &opt.addr {
        Some(a) => client_builder.address(a.to_string()),
        None => client_builder,
    };

    let ca_path = opt.ca_path.as_ref().and_then(|p| p.to_str());
    let client_builder = match ca_path {
        Some(p) => client_builder
            .add_root_certificate_filepath(p)
            .unwrap_or_else(|e| {
                error!("Failed to add ca certificate -- {:?}", e);
                std::process::exit(1);
            }),
        None => client_builder,
    };

    let client = client_builder.build().unwrap_or_else(|e| {
        error!("Failed to build client instance -- {:?}", e);
        std::process::exit(1);
    });

    let r = if opt.username == "anonymous" {
        client.auth_anonymous().await
    } else {
        let password = rpassword::prompt_password("Enter password: ").unwrap_or_else(|e| {
            error!("Failed to retrieve password - {:?}", e);
            std::process::exit(1);
        });
        client
            .auth_simple_password(opt.username.as_str(), password.as_str())
            .await
    };
    if r.is_err() {
        match r {
            Err(ClientError::Transport(value)) => {
                error!("Failed to connect to kanidm server: {}", value.to_string());
            }
            _ => error!("Error during authentication phase: {:?}", r),
        }
        std::process::exit(1);
    }

    match client
        .idm_account_get_ssh_pubkeys(opt.account_id.as_str())
        .await
    {
        Ok(pkeys) => pkeys.iter().for_each(|pkey| println!("{}", pkey)),
        Err(e) => error!("Failed to retrieve pubkeys - {:?}", e),
    }
}
