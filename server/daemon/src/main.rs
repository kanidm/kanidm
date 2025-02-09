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

#[cfg(not(any(feature = "dhat-heap", target_os = "illumos")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::fs::{metadata, File};
// This works on both unix and windows.
use fs4::fs_std::FileExt;
use kanidm_proto::messages::ConsoleOutputMode;
use sketching::otel::TracingPipelineGuard;
use std::io::Read;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use futures::{SinkExt, StreamExt};
#[cfg(not(target_family = "windows"))] // not needed for windows builds
use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
use kanidmd_core::admin::{
    AdminTaskRequest, AdminTaskResponse, ClientCodec, ProtoDomainInfo,
    ProtoDomainUpgradeCheckReport, ProtoDomainUpgradeCheckStatus,
};
use kanidmd_core::config::{Configuration, ServerConfig};
use kanidmd_core::{
    backup_server_core, cert_generate_core, create_server_core, dbscan_get_id2entry_core,
    dbscan_list_id2entry_core, dbscan_list_index_analysis_core, dbscan_list_index_core,
    dbscan_list_indexes_core, dbscan_list_quarantined_core, dbscan_quarantine_id2entry_core,
    dbscan_restore_quarantined_core, domain_rename_core, reindex_server_core, restore_server_core,
    vacuum_server_core, verify_server_core,
};
use sketching::tracing_forest::util::*;
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
            KanidmdOpt::DbScan {
                commands: DbScanOpt::GetId2Entry(dopt),
            } => &dopt.commonopts,
            KanidmdOpt::DomainSettings {
                commands: DomainSettingsCmds::Show { commonopts },
            }
            | KanidmdOpt::DomainSettings {
                commands: DomainSettingsCmds::Change { commonopts },
            }
            | KanidmdOpt::DomainSettings {
                commands: DomainSettingsCmds::UpgradeCheck { commonopts },
            }
            | KanidmdOpt::DomainSettings {
                commands: DomainSettingsCmds::Raise { commonopts },
            }
            | KanidmdOpt::DomainSettings {
                commands: DomainSettingsCmds::Remigrate { commonopts, .. },
            } => commonopts,
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
    eprintln!(
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
            let diag = kanidm_lib_file_permissions::diagnose_path(path.as_ref());
            info!(%diag);
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
                let json_output = serde_json::json!({
                    "password": password
                });
                println!("{}", json_output);
            }
            ConsoleOutputMode::Text => {
                info!(new_password = ?password)
            }
        },
        Some(Ok(AdminTaskResponse::ShowReplicationCertificate { cert })) => match output_mode {
            ConsoleOutputMode::JSON => {
                println!("{{\"certificate\":\"{}\"}}", cert)
            }
            ConsoleOutputMode::Text => {
                info!(certificate = ?cert)
            }
        },

        Some(Ok(AdminTaskResponse::DomainUpgradeCheck { report })) => {
            match output_mode {
                ConsoleOutputMode::JSON => {
                    let json_output = serde_json::json!({
                        "domain_upgrade_check": report
                    });
                    println!("{}", json_output);
                }
                ConsoleOutputMode::Text => {
                    let ProtoDomainUpgradeCheckReport {
                        name,
                        uuid,
                        current_level,
                        upgrade_level,
                        report_items,
                    } = report;

                    info!("domain_name            : {}", name);
                    info!("domain_uuid            : {}", uuid);
                    info!("domain_current_level   : {}", current_level);
                    info!("domain_upgrade_level   : {}", upgrade_level);

                    for item in report_items {
                        info!("------------------------");
                        match item.status {
                            ProtoDomainUpgradeCheckStatus::Pass6To7Gidnumber => {
                                info!("upgrade_item           : gidnumber range validity");
                                debug!("from_level             : {}", item.from_level);
                                debug!("to_level               : {}", item.to_level);
                                info!("status                 : PASS");
                            }
                            ProtoDomainUpgradeCheckStatus::Fail6To7Gidnumber => {
                                info!("upgrade_item           : gidnumber range validity");
                                debug!("from_level             : {}", item.from_level);
                                debug!("to_level               : {}", item.to_level);
                                info!("status                 : FAIL");
                                info!("description            : The automatically allocated gidnumbers for posix accounts was found to allocate numbers into systemd-reserved ranges. These can no longer be used.");
                                info!("action                 : Modify the gidnumber of affected entries so that they are in the range 65536 to 524287 OR reset the gidnumber to cause it to automatically regenerate.");
                                for entry_id in item.affected_entries {
                                    info!("affected_entry         : {}", entry_id);
                                }
                            }
                            // ===========
                            ProtoDomainUpgradeCheckStatus::Pass7To8SecurityKeys => {
                                info!("upgrade_item           : security key usage");
                                debug!("from_level             : {}", item.from_level);
                                debug!("to_level               : {}", item.to_level);
                                info!("status                 : PASS");
                            }
                            ProtoDomainUpgradeCheckStatus::Fail7To8SecurityKeys => {
                                info!("upgrade_item           : security key usage");
                                debug!("from_level             : {}", item.from_level);
                                debug!("to_level               : {}", item.to_level);
                                info!("status                 : FAIL");
                                info!("description            : Security keys no longer function as a second factor due to the introduction of CTAP2 and greater forcing PIN interactions.");
                                info!("action                 : Modify the accounts in question to remove their security key and add it as a passkey or enable TOTP");
                                for entry_id in item.affected_entries {
                                    info!("affected_entry         : {}", entry_id);
                                }
                            }
                            // ===========
                            ProtoDomainUpgradeCheckStatus::Pass7To8Oauth2StrictRedirectUri => {
                                info!("upgrade_item           : oauth2 strict redirect uri enforcement");
                                debug!("from_level             : {}", item.from_level);
                                debug!("to_level               : {}", item.to_level);
                                info!("status                 : PASS");
                            }
                            ProtoDomainUpgradeCheckStatus::Fail7To8Oauth2StrictRedirectUri => {
                                info!("upgrade_item           : oauth2 strict redirect uri enforcement");
                                debug!("from_level             : {}", item.from_level);
                                debug!("to_level               : {}", item.to_level);
                                info!("status                 : FAIL");
                                info!("description            : To harden against possible public client open redirection vulnerabilities, redirect uris must now be registered ahead of time and are validated rather than the former origin verification process.");
                                info!("action                 : Verify the redirect uri's for OAuth2 clients and then enable strict-redirect-uri on each client.");
                                for entry_id in item.affected_entries {
                                    info!("affected_entry         : {}", entry_id);
                                }
                            }
                        }
                    }
                }
            }
        }

        Some(Ok(AdminTaskResponse::DomainRaise { level })) => match output_mode {
            ConsoleOutputMode::JSON => {
                eprintln!("{{\"success\":\"{}\"}}", level)
            }
            ConsoleOutputMode::Text => {
                info!("success - raised domain level to {}", level)
            }
        },
        Some(Ok(AdminTaskResponse::DomainShow { domain_info })) => match output_mode {
            ConsoleOutputMode::JSON => {
                let json_output = serde_json::json!({
                    "domain_info": domain_info
                });
                println!("{}", json_output);
            }
            ConsoleOutputMode::Text => {
                let ProtoDomainInfo {
                    name,
                    displayname,
                    uuid,
                    level,
                } = domain_info;

                info!("domain_name   : {}", name);
                info!("domain_display: {}", displayname);
                info!("domain_uuid   : {}", uuid);
                info!("domain_level  : {}", level);
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
        Some(Ok(AdminTaskResponse::Error)) => match output_mode {
            ConsoleOutputMode::JSON => {
                eprintln!("\"error\"")
            }
            ConsoleOutputMode::Text => {
                info!("Error - you should inspect the logs.")
            }
        },
        Some(Err(err)) => {
            error!(?err, "Error during admin task operation");
        }
        None => {
            error!("Error making request to admin socket");
        }
    }
}

/// Check what we're running as and various filesystem permissions.
fn check_file_ownership(opt: &KanidmdParser) -> Result<(), ExitCode> {
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
            return Err(ExitCode::FAILURE);
        }
        (cuid, ceuid)
    };

    if let Some(cfg_path) = opt.config_path() {
        #[cfg(target_family = "unix")]
        {
            if let Some(cfg_meta) = match metadata(&cfg_path) {
                Ok(m) => Some(m),
                Err(e) => {
                    error!(
                        "Unable to read metadata for configuration file '{}' - {:?}",
                        cfg_path.display(),
                        e
                    );
                    // return ExitCxode::FAILURE;
                    None
                }
            } {
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
        }
    }
    Ok(())
}

// We have to do this because we can't use tracing until we've started the logging pipeline, and we can't start the logging pipeline until the tokio runtime's doing its thing.
async fn start_daemon(
    opt: KanidmdParser,
    mut config: Configuration,
    sconfig: ServerConfig,
) -> ExitCode {
    // if we have a server config and it has an OTEL URL, then we'll start the logging pipeline now.

    // TODO: only send to stderr when we're not in a TTY
    let sub = match sketching::otel::start_logging_pipeline(
        &sconfig.otel_grpc_url,
        sconfig.log_level.unwrap_or_default(),
        "kanidmd",
    ) {
        Err(err) => {
            eprintln!("Error starting logger - {:} - Bailing on startup!", err);
            return ExitCode::FAILURE;
        }
        Ok(val) => val,
    };

    if let Err(err) = tracing::subscriber::set_global_default(sub).map_err(|err| {
        eprintln!("Error starting logger - {:} - Bailing on startup!", err);
        ExitCode::FAILURE
    }) {
        return err;
    };

    // ************************************************
    // HERE'S WHERE YOU CAN START USING THE LOGGER
    // ************************************************

    info!(version = %env!("KANIDM_PKG_VERSION"), "Starting Kanidmd");

    // guard which shuts down the logging/tracing providers when we close out
    let _otelguard = TracingPipelineGuard {};

    // ===========================================================================
    // Start pre-run checks

    // Check the permissions of the files from the configuration.
    if let Err(err) = check_file_ownership(&opt) {
        return err;
    };

    if let Some(db_path) = sconfig.db_path.as_ref() {
        let db_pathbuf = PathBuf::from(db_path.as_str());
        // We can't check the db_path permissions because it may not exist yet!
        if let Some(db_parent_path) = db_pathbuf.parent() {
            if !db_parent_path.exists() {
                warn!(
                    "DB folder {} may not exist, server startup may FAIL!",
                    db_parent_path.to_str().unwrap_or("invalid file path")
                );
                let diag = kanidm_lib_file_permissions::diagnose_path(&db_pathbuf);
                info!(%diag);
            }

            let db_par_path_buf = db_parent_path.to_path_buf();
            let i_meta = match metadata(&db_par_path_buf) {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        "Unable to read metadata for database folder '{}' - {:?}",
                        &db_par_path_buf.to_str().unwrap_or("invalid file path"),
                        e
                    );
                    return ExitCode::FAILURE;
                }
            };
            if !i_meta.is_dir() {
                error!(
                    "ERROR: Refusing to run - DB folder {} may not be a directory",
                    db_par_path_buf.to_str().unwrap_or("invalid file path")
                );
                return ExitCode::FAILURE;
            }

            if kanidm_lib_file_permissions::readonly(&i_meta) {
                warn!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str().unwrap_or("invalid file path"));
            }
            #[cfg(not(target_os = "windows"))]
            if i_meta.mode() & 0o007 != 0 {
                warn!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str().unwrap_or("invalid file path"));
            }
        }
        config.update_db_path(db_path);
    } else {
        error!("No db_path set in configuration, server startup will FAIL!");
        return ExitCode::FAILURE;
    }

    if let Some(origin) = sconfig.origin.clone() {
        config.update_origin(&origin);
    } else {
        error!("No origin set in configuration, server startup will FAIL!");
        return ExitCode::FAILURE;
    }

    if let Some(domain) = sconfig.domain.clone() {
        config.update_domain(&domain);
    } else {
        error!("No domain set in configuration, server startup will FAIL!");
        return ExitCode::FAILURE;
    }

    config.update_db_arc_size(sconfig.get_db_arc_size());
    config.update_role(sconfig.role);
    config.update_output_mode(opt.commands.commonopt().output_mode.to_owned().into());
    config.update_trust_x_forward_for(sconfig.trust_x_forward_for);
    config.update_admin_bind_path(&sconfig.adminbindpath);
    config.update_replication_config(sconfig.repl_config.clone());

    match &opt.commands {
        // we aren't going to touch the DB so we can carry on
        KanidmdOpt::ShowReplicationCertificate { .. }
        | KanidmdOpt::RenewReplicationCertificate { .. }
        | KanidmdOpt::RefreshReplicationConsumer { .. }
        | KanidmdOpt::RecoverAccount { .. }
        | KanidmdOpt::HealthCheck(_) => (),
        _ => {
            // Okay - Lets now create our lock and go.
            #[allow(clippy::expect_used)]
            let klock_path = match sconfig.db_path.clone() {
                Some(val) => format!("{}.klock", val),
                None => std::env::temp_dir()
                    .join("kanidmd.klock")
                    .to_str()
                    .expect("Unable to create klock path, this is a critical error!")
                    .to_string(),
            };

            let flock = match File::create(&klock_path) {
                Ok(flock) => flock,
                Err(e) => {
                    error!("ERROR: Refusing to start - unable to create kanidmd exclusive lock at {} - {:?}", klock_path, e);
                    return ExitCode::FAILURE;
                }
            };

            match flock.try_lock_exclusive() {
                Ok(()) => debug!("Acquired kanidm exclusive lock"),
                Err(e) => {
                    error!("ERROR: Refusing to start - unable to lock kanidmd exclusive lock at {} - {:?}", klock_path, e);
                    error!("Is another kanidmd process running?");
                    return ExitCode::FAILURE;
                }
            };
        }
    }

    kanidm_main(sconfig, config, opt).await
}

fn main() -> ExitCode {
    // On linux when debug assertions are disabled, prevent ptrace
    // from attaching to us.
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    if let Err(code) = prctl::set_dumpable(false) {
        println!(
            "CRITICAL: Unable to set prctl flags, which breaches our security model, quitting! {:?}", code
        );
        return ExitCode::FAILURE;
    }

    // We need enough backtrace depth to find leak sources if they exist.
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::builder().trim_backtraces(Some(40)).build();

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

    if env!("KANIDM_SERVER_CONFIG_PATH").is_empty() {
        println!("CRITICAL: Kanidmd was not built correctly and is missing a valid KANIDM_SERVER_CONFIG_PATH value");
        return ExitCode::FAILURE;
    }

    let default_config_path = PathBuf::from(env!("KANIDM_SERVER_CONFIG_PATH"));

    let maybe_config_path = if let Some(p) = opt.config_path() {
        Some(p)
    } else {
        // The user didn't ask for a file, lets check if the default path exists?
        if default_config_path.exists() {
            // It does, lets use it.
            Some(default_config_path)
        } else {
            // No default config, and no config specified, lets assume the user
            // has selected environment variables.
            None
        }
    };

    let sconfig = match ServerConfig::new(maybe_config_path) {
        Ok(c) => Some(c),
        Err(e) => {
            config_error.push(format!("Config Parse failure {:?}", e));
            return ExitCode::FAILURE;
        }
    };

    // Get information on the windows username
    #[cfg(target_family = "windows")]
    get_user_details_windows();

    if !config_error.is_empty() {
        println!("There were errors on startup, which prevent the server from starting:");
        for e in config_error {
            println!(" - {}", e);
        }
        return ExitCode::FAILURE;
    }

    let sconfig = match sconfig {
        Some(val) => val,
        None => {
            println!("Somehow you got an empty ServerConfig after error checking? Cannot start!");
            return ExitCode::FAILURE;
        }
    };

    // ===========================================================================
    // Config ready

    // We always set threads to 1 unless it's the main server.
    if matches!(&opt.commands, KanidmdOpt::Server(_)) {
        // If not updated, will default to maximum
        if let Some(threads) = sconfig.thread_count {
            config.update_threads_count(threads);
        }
    } else {
        config.update_threads_count(1);
    };

    // Start the runtime

    let maybe_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.threads)
        .enable_all()
        .thread_name("kanidmd-thread-pool")
        // .thread_stack_size(8 * 1024 * 1024)
        // If we want a hook for thread start.
        // .on_thread_start()
        // In future, we can stop the whole process if a panic occurs.
        // .unhandled_panic(tokio::runtime::UnhandledPanic::ShutdownRuntime)
        .build();

    let rt = match maybe_rt {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("CRITICAL: Unable to start runtime! {:?}", err);
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(start_daemon(opt, config, sconfig))
}

/// Build and execute the main server. The ServerConfig are the configuration options
/// that we are processing into the config for the main server.
async fn kanidm_main(
    sconfig: ServerConfig,
    mut config: Configuration,
    opt: KanidmdParser,
) -> ExitCode {
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
                            "Unable to read metadata for TLS chain file '{}' - {:?}",
                            &i_path.to_str().unwrap_or("invalid file path"),
                            e
                        );
                        let diag = kanidm_lib_file_permissions::diagnose_path(&i_path);
                        info!(%diag);
                        return ExitCode::FAILURE;
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
                            "Unable to read metadata for TLS key file '{}' - {:?}",
                            &i_path.to_str().unwrap_or("invalid file path"),
                            e
                        );
                        let diag = kanidm_lib_file_permissions::diagnose_path(&i_path);
                        info!(%diag);
                        return ExitCode::FAILURE;
                    }
                };
                if !kanidm_lib_file_permissions::readonly(&i_meta) {
                    warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
                }
                #[cfg(not(target_os = "windows"))]
                if i_meta.mode() & 0o007 != 0 {
                    warn!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...", i_str);
                }
            }

            if let Some(ca_dir) = &(sconfig.tls_client_ca) {
                // check that the TLS client CA config option is what we expect
                let ca_dir_path = PathBuf::from(&ca_dir);
                if !ca_dir_path.exists() {
                    error!(
                        "TLS CA folder {} does not exist, server startup will FAIL!",
                        ca_dir
                    );
                    let diag = kanidm_lib_file_permissions::diagnose_path(&ca_dir_path);
                    info!(%diag);
                }

                let i_meta = match metadata(&ca_dir_path) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Unable to read metadata for '{}' - {:?}", ca_dir, e);
                        let diag = kanidm_lib_file_permissions::diagnose_path(&ca_dir_path);
                        info!(%diag);
                        return ExitCode::FAILURE;
                    }
                };
                if !i_meta.is_dir() {
                    error!(
                        "ERROR: Refusing to run - TLS Client CA folder {} may not be a directory",
                        ca_dir
                    );
                    return ExitCode::FAILURE;
                }
                if kanidm_lib_file_permissions::readonly(&i_meta) {
                    warn!("WARNING: TLS Client CA folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", ca_dir);
                }
                #[cfg(not(target_os = "windows"))]
                if i_meta.mode() & 0o007 != 0 {
                    warn!("WARNING: TLS Client CA folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", ca_dir);
                }
            }

            let sctx = create_server_core(config, config_test).await;
            if !config_test {
                // On linux, notify systemd.
                #[cfg(target_os = "linux")]
                {
                    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
                    // Undocumented systemd feature - all messages should have a monotonic usec sent
                    // with them. In some cases like "reloading" messages, it is undocumented but
                    // failure to send this message causes the reload to fail.
                    if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                        let _ = sd_notify::notify(true, &[monotonic_usec]);
                    } else {
                        error!("CRITICAL!!! Unable to access clock monotonic time. SYSTEMD WILL KILL US.");
                    };
                    let _ = sd_notify::notify(
                        true,
                        &[sd_notify::NotifyState::Status("Started Kanidm 🦀")],
                    );
                };

                match sctx {
                    Ok(mut sctx) => {
                        loop {
                            #[cfg(target_family = "unix")]
                            {
                                let mut listener = sctx.subscribe();
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
                                                    // Reload TLS certificates
                                                    // systemd has a special reload handler for this.
                                                    #[cfg(target_os = "linux")]
                                                    {
                                                    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Reloading]);
                                                    // CRITICAL - if you do not send a monotonic usec message after a reloading
                                                    // message, your service WILL BE KILLED.
                                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                                let _ =
                                    sd_notify::notify(true, &[monotonic_usec]);
                                } else {
                                    error!("CRITICAL!!! Unable to access clock monotonic time. SYSTEMD WILL KILL US.");
                                };
                                                    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Status("Reloading ...")]);
                                                    }

                                                    sctx.tls_acceptor_reload().await;

                                                    // Systemd freaks out if you send the ready state too fast after the
                                                    // reload state and can kill Kanidmd as a result.
                                                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                                                    #[cfg(target_os = "linux")]
                                                    {
                                                    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
                                if let Ok(monotonic_usec) = sd_notify::NotifyState::monotonic_usec_now() {
                                let _ =
                                    sd_notify::notify(true, &[monotonic_usec]);
                                } else {
                                    error!("CRITICAL!!! Unable to access clock monotonic time. SYSTEMD WILL KILL US.");
                                };
                                                    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Status("Reload Success")]);
                                                    }

                                                    info!("Reload complete");
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
                                                // we got a message on thr broadcast from somewhere else
                                                Ok(msg) = async move {
                                                    listener.recv().await
                                                } => {
                                                    debug!("Main loop received message: {:?}", msg);
                                                    break
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
                        return ExitCode::FAILURE;
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
                    return ExitCode::FAILURE;
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
                    return ExitCode::FAILURE;
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
        KanidmdOpt::ShowReplicationCertificate { commonopts } => {
            info!("Running show replication certificate ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::ShowReplicationCertificate,
                output_mode,
            )
            .await;
        }
        KanidmdOpt::RenewReplicationCertificate { commonopts } => {
            info!("Running renew replication certificate ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::RenewReplicationCertificate,
                output_mode,
            )
            .await;
        }
        KanidmdOpt::RefreshReplicationConsumer {
            commonopts,
            proceed,
        } => {
            info!("Running refresh replication consumer ...");
            if !proceed {
                error!("Unwilling to proceed. Check --help.");
            } else {
                let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
                submit_admin_req(
                    config.adminbindpath.as_str(),
                    AdminTaskRequest::RefreshReplicationConsumer,
                    output_mode,
                )
                .await;
            }
        }
        KanidmdOpt::RecoverAccount { name, commonopts } => {
            info!("Running account recovery ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::RecoverAccount {
                    name: name.to_owned(),
                },
                output_mode,
            )
            .await;
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
            commands: DbScanOpt::QuarantineId2Entry { id, commonopts: _ },
        } => {
            info!("☣️  db scan - quarantine id2 entry - {}", id);
            dbscan_quarantine_id2entry_core(&config, *id);
        }

        KanidmdOpt::DbScan {
            commands: DbScanOpt::ListQuarantined { commonopts: _ },
        } => {
            info!("☣️  db scan - list quarantined");
            dbscan_list_quarantined_core(&config);
        }

        KanidmdOpt::DbScan {
            commands: DbScanOpt::RestoreQuarantined { id, commonopts: _ },
        } => {
            info!("☣️  db scan - restore quarantined entry - {}", id);
            dbscan_restore_quarantined_core(&config, *id);
        }

        KanidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Change { .. },
        } => {
            info!("Running in domain name change mode ... this may take a long time ...");
            domain_rename_core(&config).await;
        }

        KanidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Show { commonopts },
        } => {
            info!("Running domain show ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DomainShow,
                output_mode,
            )
            .await;
        }

        KanidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::UpgradeCheck { commonopts },
        } => {
            info!("Running domain upgrade check ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DomainUpgradeCheck,
                output_mode,
            )
            .await;
        }

        KanidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Raise { commonopts },
        } => {
            info!("Running domain raise ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DomainRaise,
                output_mode,
            )
            .await;
        }

        KanidmdOpt::DomainSettings {
            commands: DomainSettingsCmds::Remigrate { commonopts, level },
        } => {
            info!("⚠️  Running domain remigrate ...");
            let output_mode: ConsoleOutputMode = commonopts.output_mode.to_owned().into();
            submit_admin_req(
                config.adminbindpath.as_str(),
                AdminTaskRequest::DomainRemigrate { level: *level },
                output_mode,
            )
            .await;
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
                false => {
                    // the replace covers when you specify an ipv6-capable "all" address
                    format!(
                        "https://{}/status",
                        config.address.replace("[::]", "localhost")
                    )
                }
            };

            info!("Checking {healthcheck_url}");

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
                            let mut cert_buf = Vec::new();
                            if let Err(err) = std::fs::File::open(&ca_cert_path)
                                .and_then(|mut file| file.read_to_end(&mut cert_buf))
                            {
                                error!(
                                    "Failed to read {:?} from filesystem: {:?}",
                                    ca_cert_path, err
                                );
                                return ExitCode::FAILURE;
                            }

                            let ca_chain_parsed =
                                match reqwest::Certificate::from_pem_bundle(&cert_buf) {
                                    Ok(val) => val,
                                    Err(e) => {
                                        error!(
                                            "Failed to parse {:?} into CA chain!\nError: {:?}",
                                            ca_cert_path, e
                                        );
                                        return ExitCode::FAILURE;
                                    }
                                };

                            // Need at least 2 certs for the leaf + chain. We skip the leaf.
                            for cert in ca_chain_parsed.into_iter().skip(1) {
                                client = client.add_root_certificate(cert)
                            }
                            client
                        }
                        false => {
                            warn!("Couldn't find ca cert {} but carrying on...", ca_cert);
                            client
                        }
                    }
                }
            };
            #[allow(clippy::unwrap_used)]
            let client = client.build().unwrap();

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
                    return ExitCode::FAILURE;
                }
            };
            debug!("Request: {req:?}");
            let output_mode: ConsoleOutputMode = sopt.commonopts.output_mode.to_owned().into();
            match output_mode {
                ConsoleOutputMode::JSON => {
                    println!("{{\"result\":\"OK\"}}")
                }
                ConsoleOutputMode::Text => {
                    info!("OK")
                }
            }
        }
        KanidmdOpt::Version(_) => {}
    }
    ExitCode::SUCCESS
}
