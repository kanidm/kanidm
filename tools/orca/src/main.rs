// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![allow(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(not(target_family = "windows"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[macro_use]
extern crate tracing;

// use hashbrown::{HashMap, HashSet};
use std::process::ExitCode;
use std::path::{Path, PathBuf};
// use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
// use uuid::Uuid;

use crate::profile::{Profile, ProfileBuilder};
// use crate::setup::config;

mod error;
// mod data;
// mod ds;
// mod generate;
// mod ipa;
mod kani;
// mod ldap;
// mod preprocess;
mod preflight;
mod profile;
mod populate;
mod state;
// mod runner;
// mod setup;

include!("./opt.rs");

impl OrcaOpt {
    fn debug(&self) -> bool {
        match self {
            OrcaOpt::Version {
                common
            } |
            OrcaOpt::SetupWizard {
                common, ..
            } |
            OrcaOpt::TestConnection {
                common, ..
            } |
            OrcaOpt::PopulateData {
                common, ..
            } |
            OrcaOpt::Preflight {
                common, ..
            }
            => common.debug,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let opt = OrcaOpt::parse();

    if opt.debug() {
        ::std::env::set_var(
            "RUST_LOG",
            "orca=debug,kanidm=debug,kanidm_client=debug,webauthn=debug",
        );
    }

    tracing_subscriber::fmt::init();

    info!("Orca - the Kanidm Load Testing Utility.");
    debug!("cli -> {:?}", opt);
    match opt {
        OrcaOpt::Version { .. } => {
            println!("orca {}", env!("KANIDM_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }

        // Build the profile and the test dimensions.
        OrcaOpt::SetupWizard {
            common: _,
            admin_password,
            idm_admin_password,
            control_uri,
            seed,
            profile_path
        } => {
            // For now I hardcoded some dimensions, but we should prompt
            // the user for these later.

            let builder = ProfileBuilder::new(
                control_uri,
                admin_password,
                idm_admin_password,
            )
                .seed(seed);

            let profile = match builder.build() {
                Ok(p) => p,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            match profile.write_to_path(&profile_path) {
                Ok(_) => {
                    return ExitCode::SUCCESS;
                }
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            }
        }

        // Test the connection
        OrcaOpt::TestConnection {
            common: _,
            profile_path,
        } => {
            let profile = match Profile::try_from(profile_path.as_path()) {
                Ok(p) => p,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            info!(
                "Performing conntest of {}",
                profile.control_uri()
            );

            match kani::KanidmOrcaClient::new(&profile).await {
                Ok(_) => {
                    info!("success");
                    return ExitCode::SUCCESS;
                }
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            }
        }

        // From the profile and test dimensions, generate the data into a state file.
        OrcaOpt::PopulateData {
            common: _,
            profile_path,
            state_path,
        } => {
            let profile = match Profile::try_from(profile_path.as_path()) {
                Ok(p) => p,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            let client = match kani::KanidmOrcaClient::new(&profile).await {
                Ok(client) => client,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            // do-it.
            let state = match populate::populate(&client, profile).await {
                Ok(s) => s,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            match state.write_to_path(&state_path) {
                Ok(_) => {
                    return ExitCode::SUCCESS;
                }
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            }
        }

        // 
        OrcaOpt::Preflight {
            common: _,
            state_path,
        } => {
            let state = match state::State::try_from(state_path.as_path()) {
                Ok(p) => p,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            match preflight::preflight(state).await {
                Ok(_) => {
                    return ExitCode::SUCCESS;
                }
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };
        }

        // Run the test based on the state file.


        /*
        OrcaOpt::Generate(opt) => generate::doit(&opt.output_path),
        OrcaOpt::PreProc(opt) => preprocess::doit(&opt.input_path, &opt.output_path),
        OrcaOpt::Setup(opt) => {
            let _ = setup::doit(&opt.target, &opt.profile_path).await;
        }
        OrcaOpt::Run(opt) => {
            let _ = runner::doit(&opt.test_type, &opt.target, &opt.profile_path).await;
            // read the profile that we are going to be using/testing
            // load the related data (if any) or generate it
            // run the test!
        }
        OrcaOpt::Configure(opt) => update_config_file(opt),
        */
    };

    // debug!("Exit");
}
