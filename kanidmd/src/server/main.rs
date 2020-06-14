#![deny(warnings)]

use std::path::PathBuf;

use kanidm::audit::LogLevel;
use kanidm::config::Configuration;
use kanidm::core::{
    backup_server_core, create_server_core, domain_rename_core, recover_account_core,
    reindex_server_core, restore_server_core, verify_server_core,
};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    /// Logging level. quiet, default, filter, verbose, perffull
    debug: Option<LogLevel>,
    #[structopt(parse(from_os_str), short = "D", long = "db_path")]
    /// Path to the server's database. If it does not exist, it will be created.
    db_path: PathBuf,
}

#[derive(Debug, StructOpt)]
struct ServerOpt {
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    /// Path to a CA certificate (PEM)
    ca_path: Option<PathBuf>,
    #[structopt(parse(from_os_str), short = "c", long = "cert")]
    /// Path to a server certificate (PEM)
    cert_path: Option<PathBuf>,
    #[structopt(parse(from_os_str), short = "k", long = "key")]
    /// Path to a server key (PEM)
    key_path: Option<PathBuf>,
    #[structopt(short = "b", long = "bindaddr")]
    /// Address to bind the webserver to. Default: 127.0.0.1:8080
    bind: Option<String>,
    #[structopt(short = "l", long = "ldapbindaddr")]
    /// If provided, start an ldap server on the address:port. Defaults to None.
    ldapbind: Option<String>,
    #[structopt(flatten)]
    commonopts: CommonOpt,
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
    Server(ServerOpt),
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
    fn debug(&self) -> Option<LogLevel> {
        match self {
            Opt::Server(sopt) => sopt.commonopts.debug.clone(),
            Opt::Verify(sopt) | Opt::Reindex(sopt) => sopt.debug.clone(),
            Opt::Backup(bopt) => bopt.commonopts.debug.clone(),
            Opt::Restore(ropt) => ropt.commonopts.debug.clone(),
            Opt::RecoverAccount(ropt) => ropt.commonopts.debug.clone(),
            Opt::DomainChange(dopt) => dopt.commonopts.debug.clone(),
        }
    }
}

#[actix_rt::main]
async fn main() {
    // Read cli args, determine if we should backup/restore
    let opt = Opt::from_args();

    // Read our config (if any)
    let mut config = Configuration::new();
    // Apply any cli overrides?

    // Configure the server logger. This could be adjusted based on what config
    // says.
    config.update_log_level(opt.debug().map(|v| v as u32));
    ::std::env::set_var("RUST_LOG", "actix_web=info,kanidm=info");

    env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .init();

    match opt {
        Opt::Server(sopt) => {
            eprintln!("Running in server mode ...");

            config.update_db_path(&sopt.commonopts.db_path);
            config.update_tls(&sopt.ca_path, &sopt.cert_path, &sopt.key_path);
            config.update_bind(&sopt.bind);
            config.update_ldapbind(&sopt.ldapbind);

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

            config.update_db_path(&bopt.commonopts.db_path);

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

            config.update_db_path(&ropt.commonopts.db_path);

            let p = match ropt.path.to_str() {
                Some(p) => p,
                None => {
                    eprintln!("Invalid restore path");
                    std::process::exit(1);
                }
            };
            restore_server_core(config, p);
        }
        Opt::Verify(vopt) => {
            eprintln!("Running in db verification mode ...");

            config.update_db_path(&vopt.db_path);
            verify_server_core(config);
        }
        Opt::RecoverAccount(raopt) => {
            eprintln!("Running account recovery ...");

            let password = rpassword::prompt_password_stderr("new password: ").unwrap();
            config.update_db_path(&raopt.commonopts.db_path);

            recover_account_core(config, raopt.name, password);
        }
        /*
        Opt::ResetServerId(vopt) => {
            eprintln!("Resetting server id. THIS WILL BREAK REPLICATION");

            config.update_db_path(&vopt.db_path);
            reset_sid_core(config);
        }
        */
        Opt::Reindex(copt) => {
            eprintln!("Running in reindex mode ...");

            config.update_db_path(&copt.db_path);
            reindex_server_core(config);
        }
        Opt::DomainChange(dopt) => {
            eprintln!("Running in domain name change mode ... this may take a long time ...");

            config.update_db_path(&dopt.commonopts.db_path);
            domain_rename_core(config, dopt.new_domain_name);
        }
    }
}
