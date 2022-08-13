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

#[macro_use]
extern crate tracing;

use std::path::PathBuf;

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

    pub async fn exec(&self) {
        match self {
            SelfOpt::Whoami(copt) => {
                let client = copt.to_client().await;

                match client.whoami().await {
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
                let client = copt.to_client().await;

                let password = match rpassword::prompt_password("Enter new password: ") {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        return;
                    }
                };

                if let Err(e) = client.idm_account_set_password(password).await {
                    error!("Error -> {:?}", e);
                }
            }
        }
    }
}

impl SystemOpt {
    pub fn debug(&self) -> bool {
        match self {
            SystemOpt::Oauth2 { commands } => commands.debug(),
            SystemOpt::Domain { commands } => commands.debug(),
        }
    }

    pub async fn exec(&self) {
        match self {
            SystemOpt::Oauth2 { commands } => commands.exec().await,
            SystemOpt::Domain { commands } => commands.exec().await,
        }
    }
}

/// Shows the version string and current git commit status at build
fn show_version() -> bool {
    let version = env!("CARGO_PKG_VERSION");
    let git_status = git_version::git_version!(cargo_prefix = "cargo:", fallback="unknown git version");
    println!("kanidm {} ({})", version, git_status);
    true
}

impl KanidmClientOpt {
    pub fn debug(&self) -> bool {
        match self {
            KanidmClientOpt::Raw { commands } => commands.debug(),
            KanidmClientOpt::Login(lopt) => lopt.debug(),
            KanidmClientOpt::Logout(lopt) => lopt.debug(),
            KanidmClientOpt::Session { commands } => commands.debug(),
            KanidmClientOpt::CSelf { commands } => commands.debug(),
            KanidmClientOpt::Account { commands } => commands.debug(),
            KanidmClientOpt::Group { commands } => commands.debug(),
            KanidmClientOpt::System { commands } => commands.debug(),
            KanidmClientOpt::Recycle { commands } => commands.debug(),
            KanidmClientOpt::Version {} => show_version(),
        }
    }

    pub async fn exec(&self) {
        match self {
            KanidmClientOpt::Raw { commands } => commands.exec().await,
            KanidmClientOpt::Login(lopt) => lopt.exec().await,
            KanidmClientOpt::Logout(lopt) => lopt.exec().await,
            KanidmClientOpt::Session { commands } => commands.exec().await,
            KanidmClientOpt::CSelf { commands } => commands.exec().await,
            KanidmClientOpt::Account { commands } => commands.exec().await,
            KanidmClientOpt::Group { commands } => commands.exec().await,
            KanidmClientOpt::System { commands } => commands.exec().await,
            KanidmClientOpt::Recycle { commands } => commands.exec().await,
            KanidmClientOpt::Version { } => (),
        }
    }
}

pub(crate) fn password_prompt(prompt: &str) -> Option<String> {
    for _ in 0..3 {
        let password = rpassword::prompt_password(prompt).ok()?;

        let password_confirm =
            rpassword::prompt_password("Retype the new password to confirm: ").ok()?;

        if password == password_confirm {
            return Some(password);
        } else {
            error!("Passwords do not match");
        }
    }
    None
}
