#![deny(warnings)]
#[macro_use]
extern crate tracing;

use std::process::ExitCode;

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
async fn main() -> ExitCode {
    let opt = ClientOpt::parse();
    if opt.debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    sketching::tracing_subscriber::fmt::init();

    debug!("Starting PAM auth tester tool ...");

    let Ok(cfg) = KanidmUnixdConfig::new()
        .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
        else {
            error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
            return ExitCode::FAILURE
        };

    let password = match rpassword::prompt_password("Enter Unix password: ") {
        Ok(p) => p,
        Err(e) => {
            error!("Problem getting input password: {}", e);
            return ExitCode::FAILURE;
        }
    };

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
    };

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
    };
    ExitCode::SUCCESS
}
