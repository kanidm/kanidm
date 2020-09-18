#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate log;
use structopt::StructOpt;

pub mod account;
pub mod common;
pub mod group;
pub mod login;
pub mod raw;
pub mod recycle;

use crate::account::AccountOpt;
use crate::common::CommonOpt;
use crate::group::GroupOpt;
use crate::login::LoginOpt;
use crate::raw::RawOpt;
use crate::recycle::RecycleOpt;

#[derive(Debug, StructOpt)]
pub enum SelfOpt {
    #[structopt(name = "whoami")]
    /// Show the current authenticated user's identity
    Whoami(CommonOpt),
    #[structopt(name = "set_password")]
    /// Set the current user's password
    SetPassword(CommonOpt),
}

impl SelfOpt {
    pub fn debug(&self) -> bool {
        match self {
            SelfOpt::Whoami(copt) => copt.debug,
            SelfOpt::SetPassword(copt) => copt.debug,
        }
    }

    pub fn exec(&self) {
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

                let password = match rpassword::prompt_password_stderr("Enter new password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.idm_account_set_password(password) {
                    eprintln!("Error -> {:?}", e);
                }
            }
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(about = "Kanidm Client Utility")]
pub enum ClientOpt {
    #[structopt(name = "login")]
    /// Login to an account to use with future cli operations
    Login(LoginOpt),
    #[structopt(name = "self")]
    /// Actions for the current authenticated account
    CSelf(SelfOpt),
    #[structopt(name = "account")]
    /// Account operations
    Account(AccountOpt),
    #[structopt(name = "group")]
    /// Group operations
    Group(GroupOpt),
    #[structopt(name = "recycle_bin")]
    /// Recycle Bin operations
    Recycle(RecycleOpt),
    #[structopt(name = "raw")]
    /// Unsafe - low level, raw database operations.
    Raw(RawOpt),
}

impl ClientOpt {
    pub fn debug(&self) -> bool {
        match self {
            ClientOpt::Raw(ropt) => ropt.debug(),
            ClientOpt::Login(lopt) => lopt.debug(),
            ClientOpt::CSelf(csopt) => csopt.debug(),
            ClientOpt::Account(aopt) => aopt.debug(),
            ClientOpt::Group(gopt) => gopt.debug(),
            ClientOpt::Recycle(ropt) => ropt.debug(),
        }
    }

    pub fn exec(&self) {
        match self {
            ClientOpt::Raw(ropt) => ropt.exec(),
            ClientOpt::Login(lopt) => lopt.exec(),
            ClientOpt::CSelf(csopt) => csopt.exec(),
            ClientOpt::Account(aopt) => aopt.exec(),
            ClientOpt::Group(gopt) => gopt.exec(),
            ClientOpt::Recycle(ropt) => ropt.exec(),
        }
    }
}

pub(crate) fn password_prompt(prompt: &str) -> Option<String> {
    for _ in 0..3 {
        let password = match rpassword::prompt_password_stderr(prompt) {
            Ok(p) => p,
            Err(_e) => return None,
        };

        let password_confirm =
            match rpassword::prompt_password_stderr("Retype the new password to confirm: ") {
                Ok(p) => p,
                Err(_e) => return None,
            };

        if password == password_confirm {
            return Some(password);
        } else {
            eprintln!("Passwords do not match");
        }
    }
    None
}
