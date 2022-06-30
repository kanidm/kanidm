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

#[cfg(not(target_family = "windows"))] // not needed for windows builds
use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};
#[cfg(target_family = "windows")] // for windows builds
use whoami;

use serde::Deserialize;
use std::fs::{metadata, File, Metadata};

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, OnlineBackup, ServerRole};
use kanidm::tracing_tree;
#[cfg(not(target_family = "windows"))]
use kanidm::utils::file_permissions_readonly;
use score::{
    backup_server_core, create_server_core, dbscan_get_id2entry_core, dbscan_list_id2entry_core,
    dbscan_list_index_analysis_core, dbscan_list_index_core, dbscan_list_indexes_core,
    domain_display_set_core, domain_rename_core, recover_account_core, reindex_server_core,
    restore_server_core, vacuum_server_core, verify_server_core,
};

use clap::{Args, Parser, Subcommand};

include!("./opt.rs");

#[derive(Debug, Deserialize)]
struct ServerConfig {
    pub bindaddress: Option<String>,
    pub ldapbindaddress: Option<String>,
    // pub threads: Option<usize>,
    pub db_path: String,
    pub db_fs_type: Option<String>,
    pub db_arc_size: Option<usize>,
    pub tls_chain: Option<String>,
    pub tls_key: Option<String>,
    pub log_level: Option<String>,
    pub online_backup: Option<OnlineBackup>,
    pub domain: String,
    pub origin: String,
    #[serde(default)]
    pub role: ServerRole,
}

impl ServerConfig {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, ()> {
        let mut f = File::open(config_path).map_err(|e| {
            eprintln!("Unable to open config file [{:?}] 🥺", e);
        })?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .map_err(|e| eprintln!("unable to read contents {:?}", e))?;

        toml::from_str(contents.as_str()).map_err(|e| eprintln!("unable to parse config {:?}", e))
    }
}

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
            } => &sopt,
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
            KanidmdOpt::SystemSettings {
                commands: SystemSettingsCmds::SetDomainDisplayName(sopt),
            } => &sopt.commonopts,
            KanidmdOpt::SystemSettings {
                commands: SystemSettingsCmds::DomainChange(sopt),
            } => &sopt,
            KanidmdOpt::Database {
                commands: DbCommands::Verify(sopt),
            }
            | KanidmdOpt::Database {
                commands: DbCommands::Reindex(sopt),
            } => &sopt,
            KanidmdOpt::Database {
                commands: DbCommands::Vacuum(copt),
            } => &copt,
        }
    }
}

fn read_file_metadata(path: &PathBuf) -> Metadata {
    match metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "Unable to read metadata for {} - {:?}",
                path.to_str().unwrap_or("invalid file path"),
                e
            );
            std::process::exit(1);
        }
    }
}

/// Gets the user details if we're running in unix-land
#[cfg(not(target_family = "windows"))]
fn get_user_details_unix() -> (u32, u32) {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
        eprintln!("WARNING: This is running as uid == 0 (root) which may be a security risk.");
        // eprintln!("ERROR: Refusing to run - this process must not operate as root.");
        // std::process::exit(1);
    }

    if cuid != ceuid || cgid != cegid {
        eprintln!("{} != {} || {} != {}", cuid, ceuid, cgid, cegid);
        eprintln!("ERROR: Refusing to run - uid and euid OR gid and egid must be consistent.");
        std::process::exit(1);
    }
    (cuid, ceuid)
}

/// Get information on the windows username
#[cfg(target_family = "windows")]
fn get_user_details_windows() {
    eprintln!(
        "Running on windows, current username is: {:?}",
        whoami::username()
    );
}

#[tokio::main]
async fn main() {
    tracing_tree::main_init();

    // Get information on the windows username
    #[cfg(target_family = "windows")]
    get_user_details_windows();

    // Get info about who we are.
    #[cfg(target_family = "unix")]
    let (cuid, ceuid) = get_user_details_unix();

    // Read cli args, determine if we should backup/restore
    let opt = KanidmdParser::parse();

    let mut config = Configuration::new();
    // Check the permissions are OK.
    #[cfg(target_family = "unix")]
    {
        let cfg_meta = read_file_metadata(&(opt.commands.commonopt().config_path));

        #[cfg(target_family = "unix")]
        if !file_permissions_readonly(&cfg_meta) {
            eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
            opt.commands.commonopt().config_path.to_str().unwrap_or("invalid file path"));
        }

        #[cfg(target_family = "unix")]
        if cfg_meta.mode() & 0o007 != 0 {
            eprintln!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...",
            opt.commands.commonopt().config_path.to_str().unwrap_or("invalid file path")
            );
        }

        #[cfg(target_family = "unix")]
        if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
            eprintln!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
            opt.commands.commonopt().config_path.to_str().unwrap_or("invalid file path")
            );
        }
    }

    // Read our config
    let sconfig = match ServerConfig::new(&(opt.commands.commonopt().config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config Parse failure {:?}", e);
            std::process::exit(1);
        }
    };
    // Apply the file requirements
    let ll = sconfig
        .log_level
        .map(|ll| match LogLevel::from_str(ll.as_str()) {
            Ok(v) => v as u32,
            Err(e) => {
                eprintln!("{:?}", e);
                std::process::exit(1);
            }
        });

    // Check the permissions of the files from the configuration.

    let db_path = PathBuf::from(sconfig.db_path.as_str());
    // We can't check the db_path permissions because it may not exist yet!
    if let Some(db_parent_path) = db_path.parent() {
        if !db_parent_path.exists() {
            eprintln!(
                "DB folder {} may not exist, server startup may FAIL!",
                db_parent_path.to_str().unwrap_or("invalid file path")
            );
        }

        let db_par_path_buf = db_parent_path.to_path_buf();
        let i_meta = read_file_metadata(&db_par_path_buf);
        if !i_meta.is_dir() {
            eprintln!(
                "ERROR: Refusing to run - DB folder {} may not be a directory",
                db_par_path_buf.to_str().unwrap_or("invalid file path")
            );
            std::process::exit(1);
        }

        // TODO: windows support for DB folder permissions checks
        #[cfg(target_family = "unix")]
        {
            if !file_permissions_readonly(&i_meta) {
                eprintln!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str().unwrap_or("invalid file path"));
            }
            if i_meta.mode() & 0o007 != 0 {
                eprintln!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str().unwrap_or("invalid file path"));
            }
        }
    }

    config.update_log_level(ll);
    config.update_db_path(&sconfig.db_path.as_str());
    config.update_db_fs_type(&sconfig.db_fs_type);
    config.update_origin(&sconfig.origin.as_str());
    config.update_domain(&sconfig.domain.as_str());
    config.update_db_arc_size(sconfig.db_arc_size);
    config.update_role(sconfig.role);
    config.update_output_mode(opt.commands.commonopt().output_mode.to_owned().into());

    // Apply any cli overrides, normally debug level.
    if let Some(dll) = opt.commands.commonopt().debug.as_ref() {
        config.update_log_level(Some(dll.clone() as u32));
    }

    // ::std::env::set_var("RUST_LOG", "tide=info,kanidm=info,webauthn=debug");
    // env_logger::builder()
    //     .format_timestamp(None)
    //     .format_level(false)
    //     .init();

    match &opt.commands {
        KanidmdOpt::Server(_sopt) | KanidmdOpt::ConfigTest(_sopt) => {
            let config_test = matches!(&opt.commands, KanidmdOpt::ConfigTest(_));
            if config_test {
                eprintln!("Running in server configuration test mode ...");
            } else {
                eprintln!("Running in server mode ...");
            };

            // configuration options that only relate to server mode
            config.update_tls(&sconfig.tls_chain, &sconfig.tls_key);
            config.update_bind(&sconfig.bindaddress);
            config.update_ldapbind(&sconfig.ldapbindaddress);
            config.update_online_backup(&sconfig.online_backup);

            if let Some(i_str) = &(sconfig.tls_chain) {
                let i_path = PathBuf::from(i_str.as_str());
                // TODO: windows support for DB folder permissions checks
                #[cfg(not(target_family = "unix"))]
                eprintln!("WARNING: permissions checks on windows aren't implemented, cannot check TLS Key at {:?}", i_path);

                #[cfg(target_family = "unix")]
                {
                    let i_meta = read_file_metadata(&i_path);
                    if !file_permissions_readonly(&i_meta) {
                        eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
                    }
                }
            }

            if let Some(i_str) = &(sconfig.tls_key) {
                let i_path = PathBuf::from(i_str.as_str());
                // TODO: windows support for DB folder permissions checks
                #[cfg(not(target_family = "unix"))]
                eprintln!("WARNING: permissions checks on windows aren't implemented, cannot check TLS Key at {:?}", i_path);

                // TODO: windows support for DB folder permissions checks
                #[cfg(target_family = "unix")]
                {
                    let i_meta = read_file_metadata(&i_path);
                    if !file_permissions_readonly(&i_meta) {
                        eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
                    }
                    if i_meta.mode() & 0o007 != 0 {
                        eprintln!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...", i_str);
                    }
                }
            }

            let sctx = create_server_core(config, config_test).await;
            if !config_test {
                match sctx {
                    Ok(_sctx) => match tokio::signal::ctrl_c().await {
                        Ok(_) => {
                            eprintln!("Ctrl-C received, shutting down");
                        }
                        Err(_) => {
                            eprintln!("Invalid signal received, shutting down as a precaution ...");
                        }
                    },
                    Err(_) => {
                        eprintln!("Failed to start server core!");
                        // We may need to return an exit code here, but that may take some re-architecting
                        // to ensure we drop everything cleanly.
                        return;
                    }
                }
                eprintln!("stopped 🛑 ");
            }
        }
        KanidmdOpt::Database {
            commands: DbCommands::Backup(bopt),
        } => {
            eprintln!("Running in backup mode ...");
            let p = match bopt.path.to_str() {
                Some(p) => p,
                None => {
                    eprintln!("Invalid backup path");
                    std::process::exit(1);
                }
            };
            backup_server_core(&config, p);
        }
        KanidmdOpt::Database {
            commands: DbCommands::Restore(ropt),
        } => {
            eprintln!("Running in restore mode ...");
            let p = match ropt.path.to_str() {
                Some(p) => p,
                None => {
                    eprintln!("Invalid restore path");
                    std::process::exit(1);
                }
            };
            restore_server_core(&config, p);
        }
        KanidmdOpt::Database {
            commands: DbCommands::Verify(_vopt),
        } => {
            eprintln!("Running in db verification mode ...");
            verify_server_core(&config);
        }
        KanidmdOpt::RecoverAccount(raopt) => {
            eprintln!("Running account recovery ...");
            recover_account_core(&config, &raopt.name);
        }
        KanidmdOpt::Database {
            commands: DbCommands::Reindex(_copt),
        } => {
            eprintln!("Running in reindex mode ...");
            reindex_server_core(&config);
        }
        KanidmdOpt::DbScan {
            commands: DbScanOpt::ListIndexes(_),
        } => {
            eprintln!("👀 db scan - list indexes");
            dbscan_list_indexes_core(&config);
        }
        KanidmdOpt::DbScan {
            commands: DbScanOpt::ListId2Entry(_),
        } => {
            eprintln!("👀 db scan - list id2entry");
            dbscan_list_id2entry_core(&config);
        }
        KanidmdOpt::DbScan {
            commands: DbScanOpt::ListIndexAnalysis(_),
        } => {
            eprintln!("👀 db scan - list index analysis");
            dbscan_list_index_analysis_core(&config);
        }
        KanidmdOpt::DbScan {
            commands: DbScanOpt::ListIndex(dopt),
        } => {
            eprintln!("👀 db scan - list index content - {}", dopt.index_name);
            dbscan_list_index_core(&config, dopt.index_name.as_str());
        }
        KanidmdOpt::DbScan {
            commands: DbScanOpt::GetId2Entry(dopt),
        } => {
            eprintln!("👀 db scan - get id2 entry - {}", dopt.id);
            dbscan_get_id2entry_core(&config, dopt.id);
        }
        KanidmdOpt::SystemSettings {
            commands: SystemSettingsCmds::SetDomainDisplayName(sopt),
        } => {
            eprintln!(
                "system settings: set domain_display_name - {:?}",
                &sopt.domain_display_name
            );
            domain_display_set_core(&config, sopt.domain_display_name.as_str())
        }
        KanidmdOpt::SystemSettings {
            commands: SystemSettingsCmds::DomainChange(_dopt),
        } => {
            eprintln!("Running in domain name change mode ... this may take a long time ...");
            domain_rename_core(&config);
        }
        KanidmdOpt::Database {
            commands: DbCommands::Vacuum(_copt),
        } => {
            eprintln!("Running in vacuum mode ...");
            vacuum_server_core(&config);
        }
    }
}
