#![deny(warnings)]

extern crate actix;
extern crate env_logger;
extern crate rpassword;

extern crate kanidm;
extern crate structopt;
#[macro_use]
extern crate log;

use kanidm::config::Configuration;
use kanidm::core::{
    backup_server_core, create_server_core, recover_account_core, reset_sid_core,
    restore_server_core, verify_server_core,
};

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct CommonOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(parse(from_os_str), short = "D", long = "db_path")]
    db_path: PathBuf,
}

#[derive(Debug, StructOpt)]
struct ServerOpt {
    #[structopt(parse(from_os_str), short = "C", long = "ca")]
    ca_path: Option<PathBuf>,
    #[structopt(parse(from_os_str), short = "c", long = "cert")]
    cert_path: Option<PathBuf>,
    #[structopt(parse(from_os_str), short = "k", long = "key")]
    key_path: Option<PathBuf>,
    #[structopt(short = "r", long = "domain")]
    domain: String,
    #[structopt(short = "b", long = "bindaddr")]
    bind: Option<String>,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct BackupOpt {
    #[structopt(parse(from_os_str))]
    path: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct RestoreOpt {
    #[structopt(parse(from_os_str))]
    path: PathBuf,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
struct RecoverAccountOpt {
    #[structopt(short)]
    name: String,
    #[structopt(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, StructOpt)]
enum Opt {
    #[structopt(name = "server")]
    Server(ServerOpt),
    #[structopt(name = "backup")]
    Backup(BackupOpt),
    #[structopt(name = "restore")]
    Restore(RestoreOpt),
    #[structopt(name = "verify")]
    Verify(CommonOpt),
    #[structopt(name = "recover_account")]
    RecoverAccount(RecoverAccountOpt),
    #[structopt(name = "reset_server_id")]
    ResetServerId(CommonOpt),
}

impl Opt {
    fn debug(&self) -> bool {
        match self {
            Opt::Server(sopt) => sopt.commonopts.debug,
            Opt::Verify(sopt) | Opt::ResetServerId(sopt) => sopt.debug,
            Opt::Backup(bopt) => bopt.commonopts.debug,
            Opt::Restore(ropt) => ropt.commonopts.debug,
            Opt::RecoverAccount(ropt) => ropt.commonopts.debug,
        }
    }
}

fn main() {
    // Read cli args, determine if we should backup/restore
    let opt = Opt::from_args();

    // Read our config (if any)
    let mut config = Configuration::new();
    // Apply any cli overrides?

    // Configure the server logger. This could be adjusted based on what config
    // says.
    if opt.debug() {
        ::std::env::set_var("RUST_LOG", "actix_web=info,kanidm=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "actix_web=info,kanidm=info");
    }
    env_logger::init();

    match opt {
        Opt::Server(sopt) => {
            info!("Running in server mode ...");

            config.update_db_path(&sopt.commonopts.db_path);
            config.update_tls(&sopt.ca_path, &sopt.cert_path, &sopt.key_path);
            config.update_bind(&sopt.bind);
            config.domain = sopt.domain.clone();

            let sys = actix::System::new("kanidm-server");
            create_server_core(config);
            let _ = sys.run();
        }
        Opt::Backup(bopt) => {
            info!("Running in backup mode ...");

            config.update_db_path(&bopt.commonopts.db_path);

            let p = match bopt.path.to_str() {
                Some(p) => p,
                None => {
                    error!("Invalid backup path");
                    std::process::exit(1);
                }
            };
            backup_server_core(config, p);
        }
        Opt::Restore(ropt) => {
            info!("Running in restore mode ...");

            config.update_db_path(&ropt.commonopts.db_path);

            let p = match ropt.path.to_str() {
                Some(p) => p,
                None => {
                    error!("Invalid restore path");
                    std::process::exit(1);
                }
            };
            restore_server_core(config, p);
        }
        Opt::Verify(vopt) => {
            info!("Running in restore mode ...");

            config.update_db_path(&vopt.db_path);
            verify_server_core(config);
        }
        Opt::RecoverAccount(raopt) => {
            info!("Running account recovery ...");

            let password = rpassword::prompt_password_stderr("new password: ").unwrap();
            config.update_db_path(&raopt.commonopts.db_path);

            recover_account_core(config, raopt.name, password);
        }
        Opt::ResetServerId(vopt) => {
            info!("Resetting server id. THIS MAY BREAK REPLICATION");

            config.update_db_path(&vopt.db_path);
            reset_sid_core(config);
        }
    }
}
