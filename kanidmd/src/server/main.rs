#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(all(jemallocator, not(test)))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use serde_derive::Deserialize;
use std::fs::{metadata, File, Metadata};

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, ServerRole};
use kanidm::core::{
    backup_server_core, create_server_core, dbscan_get_id2entry_core, dbscan_list_id2entry_core,
    dbscan_list_index_analysis_core, dbscan_list_index_core, dbscan_list_indexes_core,
    domain_rename_core, recover_account_core, reindex_server_core, restore_server_core,
    vacuum_server_core, verify_server_core,
};
use kanidm::utils::file_permissions_readonly;

use structopt::StructOpt;

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
            | KanidmdOpt::Verify(sopt)
            | KanidmdOpt::Reindex(sopt)
            | KanidmdOpt::Vacuum(sopt)
            | KanidmdOpt::DbScan(DbScanOpt::ListIndexes(sopt))
            | KanidmdOpt::DbScan(DbScanOpt::ListId2Entry(sopt))
            | KanidmdOpt::DbScan(DbScanOpt::ListIndexAnalysis(sopt)) => &sopt,
            KanidmdOpt::Backup(bopt) => &bopt.commonopts,
            KanidmdOpt::Restore(ropt) => &ropt.commonopts,
            KanidmdOpt::RecoverAccount(ropt) => &ropt.commonopts,
            KanidmdOpt::DomainChange(dopt) => &dopt.commonopts,
            KanidmdOpt::DbScan(DbScanOpt::ListIndex(dopt)) => &dopt.commonopts,
            // KanidmdOpt::DbScan(DbScanOpt::GetIndex(dopt)) => &dopt.commonopts,
            KanidmdOpt::DbScan(DbScanOpt::GetId2Entry(dopt)) => &dopt.commonopts,
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

#[tokio::main]
async fn main() {
    // Get info about who we are.
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

    // Read cli args, determine if we should backup/restore
    let opt = KanidmdOpt::from_args();

    let mut config = Configuration::new();
    // Check the permissions are sane.
    let cfg_meta = read_file_metadata(&(opt.commonopt().config_path));
    if !file_permissions_readonly(&cfg_meta) {
        eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
            opt.commonopt().config_path.to_str().unwrap_or("invalid file path"));
    }

    if cfg_meta.mode() & 0o007 != 0 {
        eprintln!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...",
            opt.commonopt().config_path.to_str().unwrap_or("invalid file path")
        );
    }

    if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
        eprintln!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
            opt.commonopt().config_path.to_str().unwrap_or("invalid file path")
        );
    }

    // Read our config
    let sconfig = match ServerConfig::new(&(opt.commonopt().config_path)) {
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

    if let Some(i_str) = &(sconfig.tls_chain) {
        let i_path = PathBuf::from(i_str.as_str());
        let i_meta = read_file_metadata(&i_path);
        if !file_permissions_readonly(&i_meta) {
            eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
        }
    }

    if let Some(i_str) = &(sconfig.tls_key) {
        let i_path = PathBuf::from(i_str.as_str());
        let i_meta = read_file_metadata(&i_path);
        if !file_permissions_readonly(&i_meta) {
            eprintln!("WARNING: permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...", i_str);
        }

        if i_meta.mode() & 0o007 != 0 {
            eprintln!("WARNING: {} has 'everyone' permission bits in the mode. This could be a security risk ...", i_str);
        }
    }

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
        if !file_permissions_readonly(&i_meta) {
            eprintln!("WARNING: DB folder permissions on {} indicate it may not be RW. This could cause the server start up to fail!", db_par_path_buf.to_str().unwrap_or("invalid file path"));
        }

        if i_meta.mode() & 0o007 != 0 {
            eprintln!("WARNING: DB folder {} has 'everyone' permission bits in the mode. This could be a security risk ...", db_par_path_buf.to_str().unwrap_or("invalid file path"));
        }
    }

    config.update_log_level(ll);
    config.update_db_path(&sconfig.db_path.as_str());
    config.update_db_fs_type(&sconfig.db_fs_type);
    config.update_tls(&sconfig.tls_chain, &sconfig.tls_key);
    config.update_bind(&sconfig.bindaddress);
    config.update_ldapbind(&sconfig.ldapbindaddress);
    config.update_origin(&sconfig.origin.as_str());
    config.update_db_arc_size(sconfig.db_arc_size);
    config.update_role(sconfig.role);

    // Apply any cli overrides, normally debug level.
    if let Some(dll) = opt.commonopt().debug.as_ref() {
        config.update_log_level(Some(dll.clone() as u32));
    }

    // ::std::env::set_var("RUST_LOG", "tide=info,kanidm=info,webauthn=debug");

    env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .init();

    match opt {
        KanidmdOpt::Server(_sopt) => {
            eprintln!("Running in server mode ...");
            let sctx = create_server_core(config).await;
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
                    return;
                }
            }
        }
        KanidmdOpt::Backup(bopt) => {
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
        KanidmdOpt::Restore(ropt) => {
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
        KanidmdOpt::Verify(_vopt) => {
            eprintln!("Running in db verification mode ...");
            verify_server_core(&config);
        }
        KanidmdOpt::RecoverAccount(raopt) => {
            eprintln!("Running account recovery ...");
            recover_account_core(&config, &raopt.name);
        }
        KanidmdOpt::Reindex(_copt) => {
            eprintln!("Running in reindex mode ...");
            reindex_server_core(&config);
        }
        KanidmdOpt::Vacuum(_copt) => {
            eprintln!("Running in vacuum mode ...");
            vacuum_server_core(&config);
        }
        KanidmdOpt::DomainChange(dopt) => {
            eprintln!("Running in domain name change mode ... this may take a long time ...");
            domain_rename_core(&config, &dopt.new_domain_name);
        }
        KanidmdOpt::DbScan(DbScanOpt::ListIndexes(_)) => {
            eprintln!("👀 db scan - list indexes");
            dbscan_list_indexes_core(&config);
        }
        KanidmdOpt::DbScan(DbScanOpt::ListId2Entry(_)) => {
            eprintln!("👀 db scan - list id2entry");
            dbscan_list_id2entry_core(&config);
        }
        KanidmdOpt::DbScan(DbScanOpt::ListIndexAnalysis(_)) => {
            eprintln!("👀 db scan - list index analysis");
            dbscan_list_index_analysis_core(&config);
        }
        KanidmdOpt::DbScan(DbScanOpt::ListIndex(dopt)) => {
            eprintln!("👀 db scan - list index content - {}", dopt.index_name);
            dbscan_list_index_core(&config, dopt.index_name.as_str());
        }
        KanidmdOpt::DbScan(DbScanOpt::GetId2Entry(dopt)) => {
            eprintln!("👀 db scan - get id2 entry - {}", dopt.id);
            dbscan_get_id2entry_core(&config, dopt.id);
        }
    }
}
