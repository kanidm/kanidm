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
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};
// use std::io;
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

            let Ok(cfg) =
                KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH)
            else {
                error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
                return ExitCode::FAILURE;
            };

            info!("Sending request for user {}", &account_id);

            let mut req = ClientRequest::PamAuthenticateInit(account_id.clone());
            loop {
                match call_daemon(cfg.sock_path.as_str(), req, cfg.unix_sock_timeout).await {
                    Ok(r) => match r {
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                            println!("auth success!");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                            println!("auth failed!");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                            debug!("User may need to be in allow_local_account_override");
                            println!("auth user unknown");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                            // Prompt for and get the password
                            let cred = match rpassword::prompt_password("Enter Unix password: ") {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("Problem getting input: {}", e);
                                    return ExitCode::FAILURE;
                                }
                            };

                            // Setup the req for the next loop.
                            req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password {
                                cred,
                            });
                            continue;
                        }
                        ClientResponse::PamAuthenticateStepResponse(_)
                        | ClientResponse::SshKeys(_)
                        | ClientResponse::NssAccounts(_)
                        | ClientResponse::NssAccount(_)
                        | ClientResponse::NssGroup(_)
                        | ClientResponse::NssGroups(_)
                        | ClientResponse::Ok
                        | ClientResponse::Error
                        | ClientResponse::PamStatus(_) => {
                            // unexpected response.
                            error!("Error: unexpected response -> {:?}", r);
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        break;
                    }
                }
            }

            let sereq = ClientRequest::PamAccountAllowed(account_id);

            match call_daemon(cfg.sock_path.as_str(), sereq, cfg.unix_sock_timeout).await {
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

            match call_daemon(cfg.sock_path.as_str(), req, cfg.unix_sock_timeout).await {
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
            println!("success");
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

            match call_daemon(cfg.sock_path.as_str(), req, cfg.unix_sock_timeout).await {
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
            println!("success");
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
                match call_daemon(cfg.sock_path.as_str(), req, cfg.unix_sock_timeout).await {
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
            println!("kanidm-unix {}", env!("KANIDM_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
