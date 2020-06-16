#![deny(warnings)]

use serde_derive::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use kanidm::audit::LogLevel;
use kanidm::config::Configuration;
use kanidm::core::{
    backup_server_core, create_server_core, domain_rename_core, recover_account_core,
    reindex_server_core, restore_server_core, verify_server_core,
};

use structopt::StructOpt;

#[derive(Debug, Deserialize)]
struct ServerConfig {
    pub bindaddress: Option<String>,
    pub ldapbindaddress: Option<String>,
    // pub threads: Option<usize>,
    pub db_path: String,
    pub tls_ca: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub log_level: Option<String>,
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

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    /// Logging level. quiet, default, filter, verbose, perffull
    debug: Option<LogLevel>,
    #[structopt(parse(from_os_str), short = "c", long = "config")]
    /// Path to the server's configuration file. If it does not exist, it will be created.
    config_path: PathBuf,
}

#[derive(Debug, StructOpt)]
struct BackupOpt {
    #[structopt(parse(from_os_str))]
    /// Output path for the backup content.
    path: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct RestoreOpt {
    #[structopt(parse(from_os_str))]
    /// Restore from this path. Should be created with "backupu".
    path: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct RecoverAccountOpt {
    #[structopt(short)]
    /// The account name to recover credentials for.
    name: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct DomainOpt {
    #[structopt(short)]
    /// The new domain name.
    new_domain_name: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum Opt {
    #[structopt(name = "server")]
    /// Start the IDM Server
    Server(CommonOpt),
    #[structopt(name = "backup")]
    /// Backup the database content (offline)
    Backup(BackupOpt),
    #[structopt(name = "restore")]
    /// Restore the database content (offline)
    Restore(RestoreOpt),
    #[structopt(name = "verify")]
    /// Verify database and entity consistency.
    Verify(CommonOpt),
    #[structopt(name = "recover_account")]
    /// Recover an account's password
    RecoverAccount(RecoverAccountOpt),
    // #[structopt(name = "reset_server_id")]
    // ResetServerId(CommonOpt),
    #[structopt(name = "reindex")]
    /// Reindex the database (offline)
    Reindex(CommonOpt),
    #[structopt(name = "domain_name_change")]
    /// Change the IDM domain name
    DomainChange(DomainOpt),
}

impl Opt {
    fn commonopt(&self) -> &CommonOpt {
        match self {
            Opt::Server(sopt) | Opt::Verify(sopt) | Opt::Reindex(sopt) => &sopt,
            Opt::Backup(bopt) => &bopt.commonopts,
            Opt::Restore(ropt) => &ropt.commonopts,
            Opt::RecoverAccount(ropt) => &ropt.commonopts,
            Opt::DomainChange(dopt) => &dopt.commonopts,
        }
    }
}

#[actix_rt::main]
async fn main() {
    // Read cli args, determine if we should backup/restore
    let opt = Opt::from_args();

    // Read our config
    let mut config = Configuration::new();
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

    config.update_log_level(ll);
    config.update_db_path(&sconfig.db_path.as_str());
    config.update_tls(&sconfig.tls_ca, &sconfig.tls_cert, &sconfig.tls_key);
    config.update_bind(&sconfig.bindaddress);
    config.update_ldapbind(&sconfig.ldapbindaddress);

    // Apply any cli overrides, normally debug level.
    config.update_log_level(opt.commonopt().debug.as_ref().map(|v| v.clone() as u32));
    ::std::env::set_var("RUST_LOG", "actix_web=info,kanidm=info");

    env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .init();

    match opt {
        Opt::Server(_sopt) => {
            eprintln!("Running in server mode ...");

            let sctx = create_server_core(config).await;
            match sctx {
                Ok(sctx) => {
                    tokio::signal::ctrl_c().await.unwrap();
                    println!("Ctrl-C received, shutting down");
                    sctx.stop()
                }
                Err(_) => {
                    eprintln!("Failed to start server core!");
                    return;
                }
            }
        }
        Opt::Backup(bopt) => {
            eprintln!("Running in backup mode ...");

            // config.update_db_path(&bopt.commonopts.db_path);

            let p = match bopt.path.to_str() {
                Some(p) => p,
                None => {
                    eprintln!("Invalid backup path");
                    std::process::exit(1);
                }
            };
            backup_server_core(config, p);
        }
        Opt::Restore(ropt) => {
            eprintln!("Running in restore mode ...");

            // config.update_db_path(&ropt.commonopts.db_path);

            let p = match ropt.path.to_str() {
                Some(p) => p,
                None => {
                    eprintln!("Invalid restore path");
                    std::process::exit(1);
                }
            };
            restore_server_core(config, p);
        }
        Opt::Verify(_vopt) => {
            eprintln!("Running in db verification mode ...");

            // config.update_db_path(&vopt.db_path);
            verify_server_core(config);
        }
        Opt::RecoverAccount(raopt) => {
            eprintln!("Running account recovery ...");

            let password = rpassword::prompt_password_stderr("new password: ").unwrap();
            // config.update_db_path(&raopt.commonopts.db_path);

            recover_account_core(config, raopt.name, password);
        }
        /*
        Opt::ResetServerId(vopt) => {
            eprintln!("Resetting server id. THIS WILL BREAK REPLICATION");

            config.update_db_path(&vopt.db_path);
            reset_sid_core(config);
        }
        */
        Opt::Reindex(_copt) => {
            eprintln!("Running in reindex mode ...");

            // config.update_db_path(&copt.db_path);
            reindex_server_core(config);
        }
        Opt::DomainChange(dopt) => {
            eprintln!("Running in domain name change mode ... this may take a long time ...");

            // config.update_db_path(&dopt.commonopts.db_path);
            domain_rename_core(config, dopt.new_domain_name);
        }
    }
}
