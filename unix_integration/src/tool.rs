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

use std::process::ExitCode;

use clap::Parser;
use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::client_sync::call_daemon_blocking;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};
use std::path::PathBuf;

include!("./opt/tool.rs");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = KanidmUnixParser::parse();

    let debug = match opt.commands {
        KanidmUnixOpt::AuthTest {
            debug,
            account_id: _,
        } => debug,
        KanidmUnixOpt::CacheClear { debug, really: _ } => debug,
        KanidmUnixOpt::CacheInvalidate { debug } => debug,
        KanidmUnixOpt::Status { debug } => debug,
        KanidmUnixOpt::Version { debug } => debug,
    };

    if debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    sketching::tracing_subscriber::fmt::init();

    match opt.commands {
        KanidmUnixOpt::AuthTest {
            debug: _,
            account_id,
        } => {
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

            let req = ClientRequest::PamAuthenticate(account_id.clone(), password);
            let sereq = ClientRequest::PamAccountAllowed(account_id);

            match call_daemon(cfg.sock_path.as_str(), req).await {
                Ok(r) => match r {
                    ClientResponse::PamStatus(Some(true)) => {
                        println!("auth success!");
                    }
                    ClientResponse::PamStatus(Some(false)) => {
                        println!("auth failed!");
                    }
                    ClientResponse::PamStatus(None) => {
                        println!("auth user unknown");
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

            match call_daemon(cfg.sock_path.as_str(), sereq).await {
                Ok(r) => match r {
                    ClientResponse::PamStatus(Some(true)) => {
                        println!("account success!");
                    }
                    ClientResponse::PamStatus(Some(false)) => {
                        println!("account failed!");
                    }
                    ClientResponse::PamStatus(None) => {
                        println!("account user unknown");
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
        KanidmUnixOpt::CacheClear { debug: _, really } => {
            debug!("Starting cache clear tool ...");

            let cfg = match KanidmUnixdConfig::new()
                .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
            {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            if !really {
                error!("Are you sure you want to proceed? If so use --really");
                return ExitCode::SUCCESS;
            }

            let req = ClientRequest::ClearCache;

            match call_daemon(cfg.sock_path.as_str(), req).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::CacheInvalidate { debug: _ } => {
            debug!("Starting cache invalidate tool ...");

            let cfg = match KanidmUnixdConfig::new()
                .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
            {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
                }
            };

            let req = ClientRequest::InvalidateCache;

            match call_daemon(cfg.sock_path.as_str(), req).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::Status { debug: _ } => {
            trace!("Starting cache status tool ...");

            let cfg = match KanidmUnixdConfig::new()
                .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
            {
                Ok(c) => c,
                Err(_e) => {
                    error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                    return ExitCode::FAILURE;
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
                match call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout) {
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
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::Version { debug: _ } => {
            println!("{}", kanidm_proto::utils::get_version("kanidm-unix"));
            ExitCode::SUCCESS
        }
    }
}
