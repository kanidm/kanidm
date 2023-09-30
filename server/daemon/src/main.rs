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

use std::fs::{metadata, File};
use std::str::FromStr;
// This works on both unix and windows.
use fs2::FileExt;
use kanidm_proto::messages::ConsoleOutputMode;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use futures::{SinkExt, StreamExt};
#[cfg(not(target_family = "windows"))] // not needed for windows builds
use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use kanidmd_core::admin::{AdminTaskRequest, AdminTaskResponse, ClientCodec};
use kanidmd_core::config::{Configuration, LogLevel, ServerConfig};
use kanidmd_core::{
    backup_server_core, cert_generate_core, create_server_core, dbscan_get_id2entry_core,
    dbscan_list_id2entry_core, dbscan_list_index_analysis_core, dbscan_list_index_core,
    dbscan_list_indexes_core, dbscan_list_quarantined_core, dbscan_quarantine_id2entry_core,
    dbscan_restore_quarantined_core, domain_rename_core, reindex_server_core, restore_server_core,
    vacuum_server_core, verify_server_core,
};
use sketching::tracing_forest::traits::*;
use sketching::tracing_forest::util::*;
use sketching::tracing_forest::{self};
use tokio::net::UnixStream;
use tokio_util::codec::Framed;
#[cfg(target_family = "windows")] // for windows builds
use whoami;

include!("./opt.rs");

impl KanidmdOpt {
    fn commonopt(&self) -> &CommonOpt {
        match self {
            KanidmdOpt::Server(sopt)
            | KanidmdOpt::CertGenerate(sopt)
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
            KanidmdOpt::DbScan {
                commands: DbScanOpt::QuarantineId2Entry { commonopts, .. },
            }
            | KanidmdOpt::DbScan {
                commands: DbScanOpt::ListQuarantined { commonopts },
            }
            | KanidmdOpt::DbScan {
                commands: DbScanOpt::RestoreQuarantined { commonopts, .. },
            }
            | KanidmdOpt::ShowReplicationCertificate { commonopts }
            | KanidmdOpt::RenewReplicationCertificate { commonopts }
            | KanidmdOpt::RefreshReplicationConsumer { commonopts, .. } => commonopts,
            KanidmdOpt::RecoverAccount { commonopts, .. } => commonopts,
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

async fn submit_admin_req(path: &str, req: AdminTaskRequest, output_mode: ConsoleOutputMode) {
    // Connect to the socket.
    let stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        Err(e) => {
            error!(err = ?e, %path, "Unable to connect to socket path");
            return;
        }
    };

    let mut reqs = Framed::new(stream, ClientCodec);

    if let Err(e) = reqs.send(req).await {
        error!(err = ?e, "Unable to send request");
        return;
    };

    if let Err(e) = reqs.flush().await {
        error!(err = ?e, "Unable to flush request");
        return;
    }

    trace!("flushed, waiting ...");

    match reqs.next().await {
        Some(Ok(AdminTaskResponse::RecoverAccount { password })) => match output_mode {
            ConsoleOutputMode::JSON => {
                eprintln!("{{\"password\":\"{}\"}}", password)
            }
            ConsoleOutputMode::Text => {
                info!(new_password = ?password)
            }
        },
        Some(Ok(AdminTaskResponse::ShowReplicationCertificate { cert })) => match output_mode {
            ConsoleOutputMode::JSON => {
                eprintln!("{{\"certificate\":\"{}\"}}", cert)
            }
            ConsoleOutputMode::Text => {
                info!(certificate = ?cert)
            }
        },
        Some(Ok(AdminTaskResponse::Success)) => match output_mode {
            ConsoleOutputMode::JSON => {
                eprintln!("\"success\"")
            }
            ConsoleOutputMode::Text => {
                info!("success")
            }
        },
        _ => {
            error!("Error making request to admin socket");
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    // Read CLI args, determine what the user has asked us to do.
    let opt = KanidmdParser::parse();

    // print the app version and bail
    if let KanidmdOpt::Version(_) = &opt.commands {
        println!("kanidmd {}", env!("KANIDM_PKG_VERSION"));
        return ExitCode::SUCCESS;
    };

    //we set up a list of these so we can set the log config THEN log out the errors.
    let mut config_error: Vec<String> = Vec::new();
    let mut config = Configuration::new();
    let cfg_path = opt
        .commands
        .commonopt()
        .config_path
        .clone()
        .or_else(|| PathBuf::from_str(env!("KANIDM_DEFAULT_CONFIG_PATH")).ok());

    let Some(cfg_path) = cfg_path else {
        eprintln!("Unable to start - can not locate any configuration file");
        return ExitCode::FAILURE;
    };

    let sconfig = match cfg_path.exists() {
        false => {
            config_error.push(format!(
                "Refusing to run - config file {} does not exist",
                cfg_path.to_str().unwrap_or("<invalid filename>")
            ));
            None
        }
        true => match ServerConfig::new(&cfg_path) {
            Ok(c) => Some(c),
            Err(e) => {
                config_error.push(format!("Config Parse failure {:?}", e));
                return ExitCode::FAILURE;
            }
        },
    };

    // We only allow config file for log level now.
    let log_filter: EnvFilter = match sconfig.as_ref() {
        Some(val) => {
            let tmp = val.log_level.clone();
            tmp.unwrap_or_default()
        }
        None => LogLevel::Info,
    }
    .into();

    // TODO: only send to stderr when we're not in a TTY
    tracing_forest::worker_task()
        .set_global(true)
        .set_tag(sketching::event_tagger)
        // Fall back to stderr
        .map_sender(|sender| {
            sender.or_stderr()

        })
        .build_on(|subscriber|{
            subscriber.with(log_filter)
        })
        .on(async {
            // Get information on the windows username
            #[cfg(target_family = "windows")]
            get_user_details_windows();

            if !config_error.is_empty() {
                for e in config_error {
                    error!("{}", e);
                }
                return ExitCode::FAILURE
            }

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

            let sconfig = match sconfig {
                Some(val) => val,
                None => {
                    error!("Somehow you got an empty ServerConfig after error checking?");
                    return ExitCode::FAILURE
                }
            };

            // Stop early if replication was found
            if sconfig.repl_config.is_some() &&
                !sconfig.i_acknowledge_that_replication_is_in_development
            {
                error!("Unable to proceed. Replication should not be configured manually.");
                return ExitCode::FAILURE
            }

            #[cfg(target_family = "unix")]
            {
                let cfg_meta = match metadata(&cfg_path) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(
                            "Unable to read metadata for '{}' - {:?}",
                            cfg_path.display(),
                            e
                        );
                        return ExitCode::FAILURE
                    }
                };

                if !kanidm_lib_file_permissions::readonly(&cfg_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                    cfg_path.to_str().unwrap_or("invalid file path"));
                }

                if cfg_meta.mode() & 0o007 != 0 {
                    warn!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...",
                    cfg_path.to_str().unwrap_or("invalid file path")
                    );
                }

                if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
                    warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                    cfg_path.to_str().unwrap_or("invalid file path")
                    );
                }
            }

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
            config.update_admin_bind_path(&sconfig.adminbindpath);

            config.update_replication_config(
                sconfig.repl_config.clone()
            );

            match &opt.commands  {
                // we aren't going to touch the DB so we can carry on
                KanidmdOpt::HealthCheck(_) => (),
                _ => {
                    // Okay - Lets now create our lock and go.
                    let klock_path = format!("{}.klock" ,sconfig.db_path.as_str());
                    let flock = match File::create(&klock_path) {
                        Ok(flock) => flock,
                        Err(e) => {
                            error!("ERROR: Refusing to start - unable to create kanidm exclusive lock at {} - {:?}", klock_path, e);
                            return ExitCode::FAILURE
                        }
                    };

                    match flock.try_lock_exclusive() {
                        Ok(()) => debug!("Acquired kanidm exclusive lock"),
                        Err(e) => {
                            error!("ERROR: Refusing to start - unable to lock kanidm exclusive lock at {} - {:?}", klock_path, e);
                            error!("Is another kanidm process running?");
                            return ExitCode::FAILURE
                        }
                    };
                }
            }

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
                        // On linux, notify systemd.
                        #[cfg(target_os = "linux")]
                        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

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
            #[allow(clippy::unwrap_used)]
                                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                                            } => {
                                                break
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
                                    #[cfg(target_family = "windows")]
                                    {
                                    tokio::select! {
                                        Ok(()) = tokio::signal::ctrl_c() => {
                                            break
                                        }
                                    }
                                    }
                                }
                                info!("Signal received, shutting down");
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
                KanidmdOpt::CertGenerate(_sopt) => {
                    info!("Running in certificate generate mode ...");
                    config.update_config_for_server_mode(&sconfig);
                    cert_generate_core(&config);
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
                KanidmdOpt::ShowReplicationCertificate {
                    commonopts
                } => {
                    info!("Running show replication certificate ...");
                    let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
                    submit_admin_req(config.adminbindpath.as_str(),
                        AdminTaskRequest::ShowReplicationCertificate,
                        output_mode,
                    ).await;
                }
                KanidmdOpt::RenewReplicationCertificate {
                    commonopts
                } => {
                    info!("Running renew replication certificate ...");
                    let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
                    submit_admin_req(config.adminbindpath.as_str(),
                        AdminTaskRequest::RenewReplicationCertificate,
                        output_mode,
                    ).await;
                }
                KanidmdOpt::RefreshReplicationConsumer {
                    commonopts,
                    proceed
                } => {
                    info!("Running refresh replication consumer ...");
                    if !proceed {
                        error!("Unwilling to proceed. Check --help.");

                    } else {
                        let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
                        submit_admin_req(config.adminbindpath.as_str(),
                            AdminTaskRequest::RefreshReplicationConsumer,
                            output_mode,
                        ).await;
                    }
                }
                KanidmdOpt::RecoverAccount {
                    name, commonopts
                } => {
                    info!("Running account recovery ...");
                    let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
                    submit_admin_req(config.adminbindpath.as_str(),
                        AdminTaskRequest::RecoverAccount { name: name.to_owned() },
                        output_mode,
                    ).await;
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

                KanidmdOpt::DbScan {
                    commands: DbScanOpt::QuarantineId2Entry {
                        id, commonopts: _
                    }
                } => {
                    info!("☣️  db scan - quarantine id2 entry - {}", id);
                    dbscan_quarantine_id2entry_core(&config, *id);
                }

                KanidmdOpt::DbScan {
                    commands: DbScanOpt::ListQuarantined {
                        commonopts: _
                    }
                } => {
                    info!("☣️  db scan - list quarantined");
                    dbscan_list_quarantined_core(&config);
                }

                KanidmdOpt::DbScan {
                    commands: DbScanOpt::RestoreQuarantined {
                        id, commonopts: _
                    }
                } => {
                    info!("☣️  db scan - restore quarantined entry - {}", id);
                    dbscan_restore_quarantined_core(&config, *id);
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

                    let healthcheck_url = match &sopt.check_origin {
                        true => format!("{}/status", config.origin),
                        false => format!("https://{}/status", config.address),
                    };

                    debug!("Checking {healthcheck_url}");

                    let mut client = reqwest::ClientBuilder::new()
                        .danger_accept_invalid_certs(!sopt.verify_tls)
                        .danger_accept_invalid_hostnames(!sopt.verify_tls)
                        .https_only(true);


                    client = match &sconfig.tls_chain {
                        None => client,
                        Some(ca_cert) => {
                            debug!("Trying to load {} to build a CA cert path", ca_cert);
                            // if the ca_cert file exists, then we'll use it
                            let ca_cert_path = PathBuf::from(ca_cert);
                            match ca_cert_path.exists() {
                                true => {
                                    let ca_contents = match std::fs::read_to_string(ca_cert_path.clone()) {
                                        Ok(val) => val,
                                        Err(e) => {
                                            error!("Failed to read {:?} from filesystem: {:?}", ca_cert_path, e);
                                            return ExitCode::FAILURE
                                        }
                                    };
                                    let content = ca_contents
                                        .split("-----END CERTIFICATE-----")
                                        .filter_map(|c| if c.trim().is_empty() { None } else { Some(c.trim().to_string())})
                                        .collect::<Vec<String>>();
                                    let content = match content.last() {
                                        Some(val) => val,
                                        None => {
                                            error!("Failed to parse {:?} as valid certificate", ca_cert_path);
                                            return ExitCode::FAILURE
                                        }
                                    };
                                    let content = format!("{}-----END CERTIFICATE-----", content);

                                    let ca_cert_parsed = match reqwest::Certificate::from_pem(content.as_bytes()) {
                                        Ok(val) => val,
                                        Err(e) =>{
                                            error!("Failed to parse {} into CA certificate!\nError: {:?}", ca_cert, e);
                                        return ExitCode::FAILURE
                                        }
                                    };
                                    client.add_root_certificate(ca_cert_parsed)
                                },
                                false => {
                                    warn!("Couldn't find ca cert {} but carrying on...", ca_cert);
                                    client
                                }
                            }
                        }
                    };
                    #[allow(clippy::unwrap_used)]
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
                    let output_mode: ConsoleOutputMode = sopt.commonopts.output_mode.to_owned().into();
                    match output_mode {
                        ConsoleOutputMode::JSON => {
                            println!("{{\"result\":\"OK\"}}")
                        },
                        ConsoleOutputMode::Text => {
                            info!("OK")
                        },
                    }

                }
                KanidmdOpt::Version(_) => {}
            }
            ExitCode::SUCCESS
        })
        .await
}
