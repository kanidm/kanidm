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
extern crate tracing;

use std::path::PathBuf;
use structopt::StructOpt;

include!("../opt/kanidm.rs");

pub mod account;
pub mod common;
pub mod domain;
pub mod group;
pub mod oauth2;
pub mod raw;
pub mod recycle;
pub mod session;

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
                    Ok(o_ent) => {
                        match o_ent {
                            Some((ent, uat)) => {
                                debug!("{:?}", ent);
                                println!("{}", uat);
                            }
                            None => {
                                error!("Authentication with cached token failed, can't query information.");
                                // TODO: remove token when we know it's not valid
                            }
                        }
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }

            SelfOpt::SetPassword(copt) => {
                let client = copt.to_client();

                let password = match rpassword::prompt_password_stderr("Enter new password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.idm_account_set_password(password) {
                    error!("Error -> {:?}", e);
                }
            }
        }
    }
}

impl SystemOpt {
    pub fn debug(&self) -> bool {
        match self {
            SystemOpt::Oauth2(oopt) => oopt.debug(),
            SystemOpt::Domain(dopt) => dopt.debug(),
        }
    }

    pub fn exec(&self) {
        match self {
            SystemOpt::Oauth2(oopt) => oopt.exec(),
            SystemOpt::Domain(dopt) => dopt.exec(),
        }
    }
}

impl KanidmClientOpt {
    pub fn debug(&self) -> bool {
        match self {
            KanidmClientOpt::Raw(ropt) => ropt.debug(),
            KanidmClientOpt::Login(lopt) => lopt.debug(),
            KanidmClientOpt::Logout(lopt) => lopt.debug(),
            KanidmClientOpt::Session(sopt) => sopt.debug(),
            KanidmClientOpt::CSelf(csopt) => csopt.debug(),
            KanidmClientOpt::Account(aopt) => aopt.debug(),
            KanidmClientOpt::Group(gopt) => gopt.debug(),
            KanidmClientOpt::System(sopt) => sopt.debug(),
            KanidmClientOpt::Recycle(ropt) => ropt.debug(),
        }
    }

    pub fn exec(&self) {
        match self {
            KanidmClientOpt::Raw(ropt) => ropt.exec(),
            KanidmClientOpt::Login(lopt) => lopt.exec(),
            KanidmClientOpt::Logout(lopt) => lopt.exec(),
            KanidmClientOpt::Session(sopt) => sopt.exec(),
            KanidmClientOpt::CSelf(csopt) => csopt.exec(),
            KanidmClientOpt::Account(aopt) => aopt.exec(),
            KanidmClientOpt::Group(gopt) => gopt.exec(),
            KanidmClientOpt::System(sopt) => sopt.exec(),
            KanidmClientOpt::Recycle(ropt) => ropt.exec(),
        }
    }
}

pub(crate) fn password_prompt(prompt: &str) -> Option<String> {
    for _ in 0..3 {
        let password = rpassword::prompt_password_stderr(prompt).ok()?;

        let password_confirm =
            rpassword::prompt_password_stderr("Retype the new password to confirm: ").ok()?;

        if password == password_confirm {
            return Some(password);
        } else {
            error!("Passwords do not match");
        }
    }
    None
}
