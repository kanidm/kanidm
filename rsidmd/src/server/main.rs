#![deny(warnings)]

extern crate actix;
extern crate env_logger;
extern crate rpassword;

extern crate rsidm;
extern crate structopt;
#[macro_use]
extern crate log;

use rsidm::config::Configuration;
use rsidm::core::{
    backup_server_core, create_server_core, recover_account_core, restore_server_core,
    verify_server_core,
};

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct ServerOpt {
    #[structopt(short = "d", long = "debug")]
    debug: bool,
    #[structopt(parse(from_os_str), short = "D", long = "db_path")]
    db_path: PathBuf,
}

#[derive(Debug, StructOpt)]
struct BackupOpt {
    #[structopt(parse(from_os_str))]
    path: PathBuf,
    #[structopt(flatten)]
    serveropts: ServerOpt,
}

#[derive(Debug, StructOpt)]
struct RestoreOpt {
    #[structopt(parse(from_os_str))]
    path: PathBuf,
    #[structopt(flatten)]
    serveropts: ServerOpt,
}

#[derive(Debug, StructOpt)]
struct RecoverAccountOpt {
    #[structopt(short)]
    name: String,
    #[structopt(flatten)]
    serveropts: ServerOpt,
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
    Verify(ServerOpt),
    #[structopt(name = "recover_account")]
    RecoverAccount(RecoverAccountOpt),
}

impl Opt {
    fn debug(&self) -> bool {
        match self {
            Opt::Server(sopt) | Opt::Verify(sopt) => sopt.debug,
            Opt::Backup(bopt) => bopt.serveropts.debug,
            Opt::Restore(ropt) => ropt.serveropts.debug,
            Opt::RecoverAccount(ropt) => ropt.serveropts.debug,
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
        ::std::env::set_var("RUST_LOG", "actix_web=info,rsidm=debug");
    } else {
        ::std::env::set_var("RUST_LOG", "actix_web=info,rsidm=info");
    }
    env_logger::init();

    match opt {
        Opt::Server(sopt) => {
            info!("Running in server mode ...");

            config.update_db_path(&sopt.db_path);

            let sys = actix::System::new("rsidm-server");
            create_server_core(config);
            let _ = sys.run();
        }
        Opt::Backup(bopt) => {
            info!("Running in backup mode ...");

            config.update_db_path(&bopt.serveropts.db_path);

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

            config.update_db_path(&ropt.serveropts.db_path);

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
            config.update_db_path(&raopt.serveropts.db_path);

            recover_account_core(config, raopt.name, password);
        }
    }
}
