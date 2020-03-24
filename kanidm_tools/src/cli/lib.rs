#[macro_use]
extern crate log;
use structopt::StructOpt;

pub mod account;
pub mod common;
pub mod group;
pub mod raw;
pub mod recycle;

use crate::account::AccountOpt;
use crate::common::CommonOpt;
use crate::group::GroupOpt;
use crate::raw::RawOpt;
use crate::recycle::RecycleOpt;

#[derive(Debug, StructOpt)]
pub enum SelfOpt {
    #[structopt(name = "whoami")]
    Whoami(CommonOpt),
    #[structopt(name = "set_password")]
    SetPassword(CommonOpt),
}

impl SelfOpt {
    pub fn debug(&self) -> bool {
        match self {
            SelfOpt::Whoami(copt) => copt.debug,
            SelfOpt::SetPassword(copt) => copt.debug,
        }
    }

    pub fn exec(&self) -> () {
        match self {
            SelfOpt::Whoami(copt) => {
                let client = copt.to_client();

                match client.whoami() {
                    Ok(o_ent) => match o_ent {
                        Some((ent, uat)) => {
                            debug!("{:?}", ent);
                            println!("{}", uat);
                        }
                        None => println!("Unauthenticated"),
                    },
                    Err(e) => println!("Error: {:?}", e),
                }
            }

            SelfOpt::SetPassword(copt) => {
                let client = copt.to_client();

                let password = rpassword::prompt_password_stderr("Enter new password: ").unwrap();

                client.idm_account_set_password(password).unwrap();
            }
        }
    }
}

#[derive(Debug, StructOpt)]
pub enum ClientOpt {
    #[structopt(name = "raw")]
    Raw(RawOpt),
    #[structopt(name = "self")]
    CSelf(SelfOpt),
    #[structopt(name = "account")]
    Account(AccountOpt),
    #[structopt(name = "group")]
    Group(GroupOpt),
    #[structopt(name = "recycle_bin")]
    Recycle(RecycleOpt),
}

impl ClientOpt {
    pub fn debug(&self) -> bool {
        match self {
            ClientOpt::Raw(ropt) => ropt.debug(),
            ClientOpt::CSelf(csopt) => csopt.debug(),
            ClientOpt::Account(aopt) => aopt.debug(),
            ClientOpt::Group(gopt) => gopt.debug(),
            ClientOpt::Recycle(ropt) => ropt.debug(),
        }
    }

    pub fn exec(&self) -> () {
        match self {
            ClientOpt::Raw(ropt) => ropt.exec(),
            ClientOpt::CSelf(csopt) => csopt.exec(),
            ClientOpt::Account(aopt) => aopt.exec(),
            ClientOpt::Group(gopt) => gopt.exec(),
            ClientOpt::Recycle(ropt) => ropt.exec(),
        }
    }
}
