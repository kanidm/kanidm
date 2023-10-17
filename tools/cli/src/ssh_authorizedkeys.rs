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
use kanidm_client::{ClientError, KanidmClient, KanidmClientBuilder};
use kanidm_proto::constants::{DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH_HOME};
use tracing::{debug, error};

include!("opt/ssh_authorizedkeys.rs");

pub(crate) fn build_configured_client(opt: &SshAuthorizedOpt) -> Result<KanidmClient, ()> {
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    #[cfg(not(test))]
    tracing_subscriber::fmt::init();
    #[cfg(test)]
    sketching::test_init();

    let config_path: String = shellexpand::tilde(DEFAULT_CLIENT_CONFIG_PATH_HOME).into_owned();
    debug!("Attempting to use config {}", DEFAULT_CLIENT_CONFIG_PATH);
    let client_builder = KanidmClientBuilder::new()
        .read_options_from_optional_config(DEFAULT_CLIENT_CONFIG_PATH)
        .and_then(|cb| {
            debug!("Attempting to use config {}", config_path);
            cb.read_options_from_optional_config(config_path)
        })
        .map_err(|e| {
            error!("Failed to parse config (if present) -- {:?}", e);
        })?;

    let client_builder = match &opt.addr {
        Some(a) => client_builder.address(a.to_string()),
        None => client_builder,
    };

    let ca_path = opt.ca_path.as_ref().and_then(|p| p.to_str());
    let client_builder = match ca_path {
        Some(p) => client_builder
            .add_root_certificate_filepath(p)
            .map_err(|e| {
                error!("Failed to add ca certificate -- {:?}", e);
            })?,
        None => client_builder,
    };

    client_builder
        .build()
        .map_err(|e| error!("Failed to build client instance -- {:?}", e))
}

// For now we lift a few things from the main.rs to use.
//
// usage: AuthorizedKeysCommand /usr/sbin/kanidm_ssh_authorizedkeys %u -H URL -D anonymous -C /etc/kanidm/ca.pem
//
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ()> {
    let opt: SshAuthorizedOpt = SshAuthorizedOpt::parse();
    let client = build_configured_client(&opt)?;

    let r = if opt.username == "anonymous" {
        client.auth_anonymous().await
    } else {
        let password = rpassword::prompt_password("Enter password: ")
            .map_err(|e| error!("Failed to retrieve password - {:?}", e))?;
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
        return Err(());
    }

    client
        .idm_account_get_ssh_pubkeys(opt.account_id.as_str())
        .await
        .map(|pkeys| pkeys.iter().for_each(|pkey| println!("{}", pkey)))
        .map_err(|e| {
            error!(
                "Failed to retrieve SSH keys for {} - {:?}",
                opt.account_id.to_string(),
                e
            )
        })
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::build_configured_client;
    use crate::SshAuthorizedOpt;
    #[test]
    fn test_build_configured_client() {
        let opt = SshAuthorizedOpt {
            debug: false,
            addr: Some("https://example.com:8443".to_string()),
            ca_path: None,
            username: "anonymous".to_string(),
            account_id: "anonymous".to_string(),
        };
        let client = build_configured_client(&opt);
        assert!(client.is_ok());
    }

    #[test]
    fn test_build_configured_client_err() {
        let opt = SshAuthorizedOpt {
            debug: false,
            addr: None,
            ca_path: Some(PathBuf::from("/etc/kanidm/ca.pem")),
            username: "anonymous".to_string(),
            account_id: "anonymous".to_string(),
        };
        let client = build_configured_client(&opt);
        assert!(client.is_err())
    }
}
