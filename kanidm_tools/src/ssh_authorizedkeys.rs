#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use kanidm_client::KanidmClientBuilder;
use std::path::PathBuf;

use log::{debug, error};
use structopt::StructOpt;

include!("opt/ssh_authorizedkeys.rs");

// For now we lift a few things from the main.rs to use.
//
// usage: AuthorizedKeysCommand /usr/sbin/kanidm_ssh_authorizedkeys %u -H URL -D anonymous -C /etc/kanidm/ca.pem
//
fn main() {
    let opt = SshAuthorizedOpt::from_args();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "kanidm=info,kanidm_client=info");
    }
    env_logger::init();

    let config_path: String = shellexpand::tilde("~/.config/kanidm").into_owned();
    debug!("Attempting to use config {}", "/etc/kanidm/config");
    let client_builder = match KanidmClientBuilder::new()
        .read_options_from_optional_config("/etc/kanidm/config")
        .and_then(|cb| {
            debug!("Attempting to use config {}", config_path);
            cb.read_options_from_optional_config(config_path)
        }) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse config (if present) -- {:?}", e);
            std::process::exit(1);
        }
    };

    let client_builder = match &opt.addr {
        Some(a) => client_builder.address(a.to_string()),
        None => client_builder,
    };

    let ca_path: Option<&str> = opt.ca_path.as_ref().map(|p| p.to_str()).flatten();
    let client_builder = match ca_path {
        Some(p) => match client_builder.add_root_certificate_filepath(p) {
            Ok(cb) => cb,
            Err(e) => {
                error!("Failed to add ca certificate -- {:?}", e);
                std::process::exit(1);
            }
        },
        None => client_builder,
    };

    let mut client = match client_builder.build() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build client instance -- {:?}", e);
            std::process::exit(1);
        }
    };

    let r = if opt.username == "anonymous" {
        client.auth_anonymous()
    } else {
        let password = match rpassword::prompt_password_stderr("Enter password: ") {
            Ok(pw) => pw,
            Err(e) => {
                error!("Failed to retrieve password - {:?}", e);
                std::process::exit(1);
            }
        };
        client.auth_simple_password(opt.username.as_str(), password.as_str())
    };

    if r.is_err() {
        eprintln!("Error during authentication phase: {:?}", r);
        std::process::exit(1);
    }

    match client.idm_account_get_ssh_pubkeys(opt.account_id.as_str()) {
        Ok(pkeys) => pkeys.iter().for_each(|pkey| println!("{}", pkey)),
        Err(e) => error!("Failed to retrieve pubkeys - {:?}", e),
    }
}
