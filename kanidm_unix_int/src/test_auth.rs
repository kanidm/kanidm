#![deny(warnings)]
#[macro_use]
extern crate tracing;

use clap::Parser;
use futures::executor::block_on;
use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

#[derive(Debug, Parser)]
struct ClientOpt {
    #[clap(short, long)]
    debug: bool,
    #[clap(short = 'D', long = "name")]
    account_id: String,
}

#[tokio::main]
async fn main() {
    let opt = ClientOpt::parse();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    sketching::tracing_subscriber::fmt::init();

    debug!("Starting PAM auth tester tool ...");

    let cfg = KanidmUnixdConfig::new()
        .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
        .unwrap_or_else(|_| panic!("Failed to parse {}", DEFAULT_CONFIG_PATH));

    let password = rpassword::prompt_password("Enter Unix password: ").unwrap();

    let req = ClientRequest::PamAuthenticate(opt.account_id.clone(), password);
    let sereq = ClientRequest::PamAccountAllowed(opt.account_id);

    match block_on(call_daemon(cfg.sock_path.as_str(), req)) {
        Ok(r) => match r {
            ClientResponse::PamStatus(Some(true)) => {
                info!("auth success!");
            }
            ClientResponse::PamStatus(Some(false)) => {
                info!("auth failed!");
            }
            ClientResponse::PamStatus(None) => {
                info!("user unknown");
            }
            _ => {
                // unexpected response.
                error!("Error: unexpected response -> {:?}", r);
            }
        },
        Err(e) => {
            error!("Error -> {:?}", e);
        }
    }

    match block_on(call_daemon(cfg.sock_path.as_str(), sereq)) {
        Ok(r) => match r {
            ClientResponse::PamStatus(Some(true)) => {
                info!("auth success!");
            }
            ClientResponse::PamStatus(Some(false)) => {
                info!("auth failed!");
            }
            ClientResponse::PamStatus(None) => {
                info!("user unknown");
            }
            _ => {
                // unexpected response.
                error!("Error: unexpected response -> {:?}", r);
            }
        },
        Err(e) => {
            error!("Error -> {:?}", e);
        }
    }
}
