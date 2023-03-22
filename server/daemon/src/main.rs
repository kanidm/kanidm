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

#[cfg(not(target_family = "windows"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::fs::metadata;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use kanidmd_core::config::{Configuration, ServerConfig};
use kanidmd_core::{
    backup_server_core, create_server_core, dbscan_get_id2entry_core, dbscan_list_id2entry_core,
    dbscan_list_index_analysis_core, dbscan_list_index_core, dbscan_list_indexes_core,
    domain_rename_core, recover_account_core, reindex_server_core, restore_server_core,
    vacuum_server_core, verify_server_core,
};
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
#[cfg(not(target_family = "windows"))] // not needed for windows builds
use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
#[cfg(target_family = "windows")] // for windows builds
use whoami;

include!("./opt.rs");

impl KanidmdOpt {
    fn commonopt(&self) -> &CommonOpt {
        match self {
            KanidmdOpt::Server(sopt)
            | KanidmdOpt::ConfigTest(sopt)
            | KanidmdOpt::DbScan {
                commands: DbScanOpt::ListIndexes(sopt),
            }
            | KanidmdOpt::DbScan {
                commands: DbScanOpt::ListId2Entry(sopt),
            }
            | KanidmdOpt::DbScan {
                commands: DbScanOpt::ListIndexAnalysis(sopt),
            } => sopt,
            KanidmdOpt::Database {
                commands: DbCommands::Backup(bopt),
            } => &bopt.commonopts,
            KanidmdOpt::Database {
                commands: DbCommands::Restore(ropt),
            } => &ropt.commonopts,
            KanidmdOpt::RecoverAccount(ropt) => &ropt.commonopts,
            KanidmdOpt::DbScan {
                commands: DbScanOpt::ListIndex(dopt),
            } => &dopt.commonopts,
            // KanidmdOpt::DbScan(DbScanOpt::GetIndex(dopt)) => &dopt.commonopts,
            KanidmdOpt::DbScan {
                commands: DbScanOpt::GetId2Entry(dopt),
            } => &dopt.commonopts,
            KanidmdOpt::DomainSettings {
                commands: DomainSettingsCmds::DomainChange(sopt),
            } => sopt,
            KanidmdOpt::Database {
                commands: DbCommands::Verify(sopt),
            }
            | KanidmdOpt::Database {
                commands: DbCommands::Reindex(sopt),
            } => sopt,
            KanidmdOpt::Database {
                commands: DbCommands::Vacuum(copt),
            } => copt,
            KanidmdOpt::HealthCheck(hcopt) => &hcopt.commonopts,
            KanidmdOpt::Version(copt) => copt,
        }
    }
}

/// Get information on the windows username
#[cfg(target_family = "windows")]
fn get_user_details_windows() {
    debug!(
        "Running on windows, current username is: {:?}",
        whoami::username()
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    tracing_forest::worker_task()
        .set_global(true)
        .set_tag(sketching::event_tagger)
        // Fall back to stderr
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| subscriber
            .with(EnvFilter::try_from_default_env()
                .or_else(|_| EnvFilter::try_new("info"))
                .expect("Failed to init envfilter")
            )
        )
        .on(async {
            // Get information on the windows username
            #[cfg(target_family = "windows")]
            get_user_details_windows();

            // Get info about who we are.
            #[cfg(target_family = "unix")]
            let (cuid, ceuid) = {
                let cuid = get_current_uid();
                let ceuid = get_effective_uid();
                let cgid = get_current_gid();
                let cegid = get_effective_gid();

                if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
                    warn!("This is running as uid == 0 (root) which may be a security risk.");
                    // eprintln!("ERROR: Refusing to run - this process must not operate as root.");
                    // std::process::exit(1);
                }

                if cuid != ceuid || cgid != cegid {
                    error!("{} != {} || {} != {}", cuid, ceuid, cgid, cegid);
                    error!("Refusing to run - uid and euid OR gid and egid must be consistent.");
                    return ExitCode::FAILURE
                }
                (cuid, ceuid)
            };

            // Read cli args, determine if we should backup/restore
            let opt = KanidmdParser::parse();

            // print the app version and bail
            if let KanidmdOpt::Version(_) = &opt.commands {
                kanidm_proto::utils::show_version("kanidmd");
                return ExitCode::SUCCESS
            };

            let mut config = Configuration::new();
            // Check the permissions are OK.
            #[cfg(target_family = "unix")]
            {
                let cfg_path = &opt.commands.commonopt().config_path;
                let cfg_meta = match metadata(cfg_path) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(
                            "Unable to read metadata for '{}' - {:?}",
                            cfg_path.to_str().unwrap_or("invalid file path"),
                            e
                        );
                        return ExitCode::FAILURE
                    }
                };

                if !kanidm_lib_file_permissions::readonly(&cfg_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                    opt.commands.commonopt().config_path.to_str().unwrap_or("invalid file path"));
                }

                if cfg_meta.mode() & 0o007 != 0 {
                    warn!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...",
                    opt.commands.commonopt().config_path.to_str().unwrap_or("invalid file path")
                    );
                }

                if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
                    warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                    opt.commands.commonopt().config_path.to_str().unwrap_or("invalid file path")
                    );
                }
            }

            // Read our config
            let sconfig = match ServerConfig::new(&(opt.commands.commonopt().config_path)) {
                Ok(c) => c,
                Err(e) => {
                    error!("Config Parse failure {:?}", e);
                    return ExitCode::FAILURE
                }
            };
            // Check the permissions of the files from the configuration.

            let db_path = PathBuf::from(sconfig.db_path.as_str());
            // We can't check the db_path permissions because it may not exist yet!
            if let Some(db_parent_path) = db_path.parent() {
                if !db_parent_path.exists() {
                    warn!(
                        "DB folder {} may not exist, server startup may FAIL!",
                        db_parent_path.to_str().unwrap_or("invalid file path")
                    );
                }

                let db_par_path_buf = db_parent_path.to_path_buf();
                let i_meta = match metadata(&db_par_path_buf) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(
                            "Unable to read metadata for '{}' - {:?}",
                            &db_par_path_buf.to_str().unwrap_or("invalid file path"),
                            e
                        );
                        return ExitCode::FAILURE
                    }
                };
                if !i_meta.is_dir() {
                    error!(
                        "ERROR: Refusing to run - DB folder {} may not be a directory",
                        db_par_path_buf.to_str().unwrap_or("invalid file path")
                    );
                    return ExitCode::FAILURE
                }

                if kanidm_lib_file_permissions::readonly(&i_meta) {
                    warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str().unwrap_or("invalid file path"));
                }
                #[cfg(not(target_os="windows"))]
                if i_meta.mode() & 0o007 != 0 {
                    warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str().unwrap_or("invalid file path"));
                }
            }

            config.update_db_path(sconfig.db_path.as_str());
            config.update_db_fs_type(&sconfig.db_fs_type);
            config.update_origin(sconfig.origin.as_str());
            config.update_domain(sconfig.domain.as_str());
            config.update_db_arc_size(sconfig.db_arc_size);
            config.update_role(sconfig.role);
            config.update_output_mode(opt.commands.commonopt().output_mode.to_owned().into());
            config.update_trust_x_forward_for(sconfig.trust_x_forward_for);

            /*
            // Apply any cli overrides, normally debug level.
            if opt.commands.commonopt().debug.as_ref() {
                // ::std::env::set_var("RUST_LOG", "tide=info,kanidm=info,webauthn=debug");
            }
            */

            match &opt.commands {
                KanidmdOpt::Server(_sopt) | KanidmdOpt::ConfigTest(_sopt) => {
                    let config_test = matches!(&opt.commands, KanidmdOpt::ConfigTest(_));
                    if config_test {
                        info!("Running in server configuration test mode ...");
                    } else {
                        info!("Running in server mode ...");
                    };

                    // configuration options that only relate to server mode
                    config.update_config_for_server_mode(&sconfig);

                    if let Some(i_str) = &(sconfig.tls_chain) {
                        let i_path = PathBuf::from(i_str.as_str());
                        let i_meta = match metadata(&i_path) {
                            Ok(m) => m,
                            Err(e) => {
                                error!(
                                    "Unable to read metadata for '{}' - {:?}",
                                    &i_path.to_str().unwrap_or("invalid file path"),
                                    e
                                );
                                return ExitCode::FAILURE
                            }
                        };
                        if !kanidm_lib_file_permissions::readonly(&i_meta) {
                            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
                        }
                    }

                    if let Some(i_str) = &(sconfig.tls_key) {
                        let i_path = PathBuf::from(i_str.as_str());

                        let i_meta = match metadata(&i_path) {
                            Ok(m) => m,
                            Err(e) => {
                                error!(
                                    "Unable to read metadata for '{}' - {:?}",
                                    &i_path.to_str().unwrap_or("invalid file path"),
                                    e
                                );
                                return ExitCode::FAILURE
                            }
                        };
                        if !kanidm_lib_file_permissions::readonly(&i_meta) {
                            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
                        }
                        #[cfg(not(target_os="windows"))]
                        if i_meta.mode() & 0o007 != 0 {
                            warn!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...", i_str);
                        }
                    }

                    let sctx = create_server_core(config, config_test).await;
                    if !config_test {
                        match sctx {
                            Ok(mut sctx) => {
                                loop {
                                    #[cfg(target_family = "unix")]
                                    {
                                        tokio::select! {
                                            Ok(()) = tokio::signal::ctrl_c() => {
                                                break
                                            }
                                            Some(()) = async move {
                                                let sigterm = tokio::signal::unix::SignalKind::terminate();
                                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                                            } => {
                                                break
                                            }
                                            Some(()) = async move {
                                                let sigterm = tokio::signal::unix::SignalKind::alarm();
                                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                                            } => {
                                                // Ignore
                                            }
                                            Some(()) = async move {
                                                let sigterm = tokio::signal::unix::SignalKind::hangup();
                                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                                            } => {
                                                // Ignore
                                            }
                                            Some(()) = async move {
                                                let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                                            } => {
                                                // Ignore
                                            }
                                            Some(()) = async move {
                                                let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                                            } => {
                                                // Ignore
                                            }
                                        }
                                    }
                                    #[cfg(target_family = "windows")]
                                    {
                                    tokio::select! {
                                        Ok(()) = tokio::signal::ctrl_c() => {
                                            break
                                        }
                                    }
                                    }
                                }
                                debug!("Signal received, shutting down");
                                // Send a broadcast that we are done.
                                sctx.shutdown().await;
                            }
                            Err(_) => {
                                error!("Failed to start server core!");
                                // We may need to return an exit code here, but that may take some re-architecting
                                // to ensure we drop everything cleanly.
                                return ExitCode::FAILURE
                            }
                        }
                        info!("Stopped 🛑 ");
                    }


                }
                KanidmdOpt::Database {
                    commands: DbCommands::Backup(bopt),
                } => {
                    info!("Running in backup mode ...");
                    let p = match bopt.path.to_str() {
                        Some(p) => p,
                        None => {
                            error!("Invalid backup path");
                            return ExitCode::FAILURE
                        }
                    };
                    backup_server_core(&config, p);
                }
                KanidmdOpt::Database {
                    commands: DbCommands::Restore(ropt),
                } => {
                    info!("Running in restore mode ...");
                    let p = match ropt.path.to_str() {
                        Some(p) => p,
                        None => {
                            error!("Invalid restore path");
                            return ExitCode::FAILURE
                        }
                    };
                    restore_server_core(&config, p).await;
                }
                KanidmdOpt::Database {
                    commands: DbCommands::Verify(_vopt),
                } => {
                    info!("Running in db verification mode ...");
                    verify_server_core(&config).await;
                }
                KanidmdOpt::RecoverAccount(raopt) => {
                    info!("Running account recovery ...");
                    recover_account_core(&config, &raopt.name).await;
                }
                KanidmdOpt::Database {
                    commands: DbCommands::Reindex(_copt),
                } => {
                    info!("Running in reindex mode ...");
                    reindex_server_core(&config).await;
                }
                KanidmdOpt::DbScan {
                    commands: DbScanOpt::ListIndexes(_),
                } => {
                    info!("👀 db scan - list indexes");
                    dbscan_list_indexes_core(&config);
                }
                KanidmdOpt::DbScan {
                    commands: DbScanOpt::ListId2Entry(_),
                } => {
                    info!("👀 db scan - list id2entry");
                    dbscan_list_id2entry_core(&config);
                }
                KanidmdOpt::DbScan {
                    commands: DbScanOpt::ListIndexAnalysis(_),
                } => {
                    info!("👀 db scan - list index analysis");
                    dbscan_list_index_analysis_core(&config);
                }
                KanidmdOpt::DbScan {
                    commands: DbScanOpt::ListIndex(dopt),
                } => {
                    info!("👀 db scan - list index content - {}", dopt.index_name);
                    dbscan_list_index_core(&config, dopt.index_name.as_str());
                }
                KanidmdOpt::DbScan {
                    commands: DbScanOpt::GetId2Entry(dopt),
                } => {
                    info!("👀 db scan - get id2 entry - {}", dopt.id);
                    dbscan_get_id2entry_core(&config, dopt.id);
                }
                KanidmdOpt::DomainSettings {
                    commands: DomainSettingsCmds::DomainChange(_dopt),
                } => {
                    info!("Running in domain name change mode ... this may take a long time ...");
                    domain_rename_core(&config).await;
                }
                KanidmdOpt::Database {
                    commands: DbCommands::Vacuum(_copt),
                } => {
                    info!("Running in vacuum mode ...");
                    vacuum_server_core(&config);
                }
                KanidmdOpt::HealthCheck(sopt) => {
                    config.update_config_for_server_mode(&sconfig);

                    debug!("{sopt:?}");

                    let healthcheck_url = format!("https://{}/status", config.address);
                    debug!("Checking {healthcheck_url}");



                    let client = reqwest::ClientBuilder::new()
                        .danger_accept_invalid_certs(sopt.no_verify_tls)
                        .danger_accept_invalid_hostnames(sopt.no_verify_tls)
                        .https_only(true);
                    // TODO: work out how to pull the CA from the chain
                    // client = match config.tls_config {
                    //     Some(tls_config) => {
                    //         eprintln!("{:?}", tls_config);
                    //         let mut buf = Vec::new();
                    //         File::open(tls_config.chain)
                    //             .unwrap()
                    //             .read_to_end(&mut buf)
                    //             .unwrap();
                    //         eprintln!("buf: {:?}", buf);
                    //         match reqwest::Certificate::from_pem(&buf){
                    //             Ok(cert) => client.add_root_certificate(cert),
                    //             Err(err) => {
                    //                 error!("Failed to read TLS chain: {err:?}");
                    //                 client
                    //             }
                    //         }

                    //     },
                    //     None => client,
                    // };

                    let client = client
                        .build()
                        .unwrap();


                        let req = match client.get(&healthcheck_url).send().await {
                        Ok(val) => val,
                        Err(error) => {
                            let error_message = {
                                if error.is_timeout() {
                                    format!("Timeout connecting to url={healthcheck_url}")
                                } else if error.is_connect() {
                                    format!("Connection failed: {}", error)
                                } else {
                                    format!("Failed to complete healthcheck: {:?}", error)
                                }
                            };
                            error!("CRITICAL: {error_message}");
                            return ExitCode::FAILURE
                        }
                    };
                    debug!("Request: {req:?}");
                    info!("OK")
                }
                KanidmdOpt::Version(_) => {}
            }
            ExitCode::SUCCESS
        })
        .await
}
