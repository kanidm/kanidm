// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![allow(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(not(any(target_family = "windows", target_os = "illumos")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[macro_use]
extern crate tracing;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use crate::profile::{Profile, ProfileBuilder};

use tokio::{runtime::Runtime, sync::broadcast};

mod error;
mod generate;
mod kani;
mod model;
mod models;
mod populate;
mod profile;
mod run;
mod state;
mod stats;

include!("./opt.rs");

impl OrcaOpt {
    fn debug(&self) -> bool {
        match self {
            OrcaOpt::Version { common }
            | OrcaOpt::SetupWizard { common, .. }
            | OrcaOpt::TestConnection { common, .. }
            | OrcaOpt::GenerateData { common, .. }
            | OrcaOpt::PopulateData { common, .. }
            | OrcaOpt::Run { common, .. } => common.debug,
        }
    }
}

fn main() -> ExitCode {
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
            profile_path,
            threads,
        } => {
            // For now I hardcoded some dimensions, but we should prompt
            // the user for these later.

            let seed = seed.map(|seed| {
                if seed < 0 {
                    seed.wrapping_mul(-1) as u64
                } else {
                    seed as u64
                }
            });

            let builder =
                ProfileBuilder::new(control_uri, admin_password, idm_admin_password, threads)
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

            info!("Performing conntest of {}", profile.control_uri());

            // we're okay with just one thread here
            let runtime = create_tokio_runtime(Some(1));
            return runtime.block_on(async {
                match kani::KanidmOrcaClient::new(&profile).await {
                    Ok(_) => {
                        info!("success");
                        return ExitCode::SUCCESS;
                    }
                    Err(_err) => {
                        return ExitCode::FAILURE;
                    }
                }
            });
        }

        // From the profile and test dimensions, generate the data into a state file.
        OrcaOpt::GenerateData {
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

            //here we want all threads available to speed up the process.
            let runtime = create_tokio_runtime(None);

            return runtime.block_on(async {
                let client = match kani::KanidmOrcaClient::new(&profile).await {
                    Ok(client) => client,
                    Err(_err) => {
                        return ExitCode::FAILURE;
                    }
                };

                // do-it.
                let state = match generate::populate(&client, profile).await {
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
            });
        }

        //
        OrcaOpt::PopulateData {
            common: _,
            state_path,
        } => {
            let state = match state::State::try_from(state_path.as_path()) {
                Ok(p) => p,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };

            //here we want all threads available to speed up the process.
            let runtime = create_tokio_runtime(None);

            return runtime.block_on(async {
                match populate::preflight(state).await {
                    Ok(_) => {
                        return ExitCode::SUCCESS;
                    }
                    Err(_err) => {
                        return ExitCode::FAILURE;
                    }
                };
            });
        }

        // Run the test based on the state file.
        OrcaOpt::Run {
            common: _,
            state_path,
        } => {
            let state = match state::State::try_from(state_path.as_path()) {
                Ok(p) => p,
                Err(_err) => {
                    return ExitCode::FAILURE;
                }
            };
            let runtime = create_tokio_runtime(state.thread_count);
            // We have a broadcast channel setup for controlling the state of
            // various actors and parts.
            //
            // We want a small amount of backlog because there are a few possible
            // commands that could be sent.
            return runtime.block_on(async {
                let (control_tx, control_rx) = broadcast::channel(8);

                let mut run_execute = tokio::task::spawn(run::execute(state, control_rx));

                loop {
                    tokio::select! {
                        // Note that we pass a &mut handle here because we want the future to join
                        // but not be consumed each loop iteration.
                        result = &mut run_execute => {
                            match result {
                                Ok(_) => {
                                    return ExitCode::SUCCESS;
                                }
                                Err(_err) => {
                                    return ExitCode::FAILURE;
                                }
                            };
                        }
                        // Signal handling.
                        Ok(()) = tokio::signal::ctrl_c() => {
                            info!("Stopping Task ...");
                            let _ = control_tx.send(run::Signal::Stop);
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::terminate();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Kill it with fire I guess.
                            return ExitCode::FAILURE;
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::alarm();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::hangup();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                        Some(()) = async move {
                            let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                            #[allow(clippy::unwrap_used)]
                            tokio::signal::unix::signal(sigterm).unwrap().recv().await
                        } => {
                            // Ignore
                        }
                    }
                }
            });
        }
    };
}

fn create_tokio_runtime(threads: Option<usize>) -> Runtime {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    match threads {
        Some(threads) => builder.worker_threads(threads),
        None => &mut builder,
    }
    .enable_all()
    .build()
    .expect("Failed to start tokio runtime")
}
