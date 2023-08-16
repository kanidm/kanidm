#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]
#![allow(warnings)]
#[macro_use]
extern crate tracing;

use crate::common::OpType;
use async_recursion::async_recursion;
use dialoguer::{console::Term, theme::ColorfulTheme, Confirm, Input};
use kanidm_client::KanidmClient;
use kanidm_proto::internal::{IdentifyUserRequest, IdentifyUserResponse};
use regex::Regex;
use std::{
    io::{stdin, stdout, Write},
    path::PathBuf,
    time::{Duration, SystemTime},
};
use tokio::{runtime, task, time::interval};
use url::Url;
use uuid::Uuid;

include!("../opt/kanidm.rs");

pub mod badlist;
pub mod common;
pub mod domain;
pub mod group;
pub mod oauth2;
pub mod person;
pub mod raw;
pub mod recycle;
pub mod serviceaccount;
pub mod session;
pub mod session_expiry;
pub mod synch;
mod webauthn;

impl SelfOpt {
    pub fn debug(&self) -> bool {
        match self {
            SelfOpt::Whoami(copt) => copt.debug,
            SelfOpt::IdentifyUser(copt) => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            SelfOpt::Whoami(copt) => {
                let client = copt.to_client(OpType::Read).await;

                match client.whoami().await {
                    Ok(o_ent) => {
                        match o_ent {
                            Some(ent) => {
                                println!("{}", ent);
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
            SelfOpt::IdentifyUser(copt) => {
                let client = copt.to_client(OpType::Write).await;
                let whoami_response = match client.whoami().await {
                    Ok(o_ent) => {
                        match o_ent {
                            Some(ent) => ent,
                            None => {
                                eprintln!("Authentication with cached token failed, can't query information.");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                        return;
                    }
                };

                let spn = match whoami_response
                    .attrs
                    .get("spn")
                    .map(|v| v.first())
                    .flatten()
                {
                    Some(spn) => spn.as_str(),
                    None => {
                        eprintln!("Failed to retrieve the id from whoami response :/\nExiting....");
                        return;
                    }
                };
                identify_user_exec(IdentifyUserState::Start, client, spn, None).await;
            } // end PersonOpt::Validity
        }
    }
}

impl SystemOpt {
    pub fn debug(&self) -> bool {
        match self {
            SystemOpt::PwBadlist { commands } => commands.debug(),
            SystemOpt::Oauth2 { commands } => commands.debug(),
            SystemOpt::Domain { commands } => commands.debug(),
            SystemOpt::Synch { commands } => commands.debug(),
            SystemOpt::AuthSessionExpiry { commands } => commands.debug(),
            SystemOpt::PrivilegedSessionExpiry { commands } => commands.debug(),
        }
    }

    pub async fn exec(&self) {
        match self {
            SystemOpt::PwBadlist { commands } => commands.exec().await,
            SystemOpt::Oauth2 { commands } => commands.exec().await,
            SystemOpt::Domain { commands } => commands.exec().await,
            SystemOpt::Synch { commands } => commands.exec().await,
            SystemOpt::AuthSessionExpiry { commands } => commands.exec().await,
            SystemOpt::PrivilegedSessionExpiry { commands } => commands.exec().await,
        }
    }
}

impl KanidmClientOpt {
    pub fn debug(&self) -> bool {
        match self {
            KanidmClientOpt::Raw { commands } => commands.debug(),
            KanidmClientOpt::Login(lopt) => lopt.debug(),
            KanidmClientOpt::Reauth(lopt) => lopt.debug(),
            KanidmClientOpt::Logout(lopt) => lopt.debug(),
            KanidmClientOpt::Session { commands } => commands.debug(),
            KanidmClientOpt::CSelf { commands } => commands.debug(),
            KanidmClientOpt::Group { commands } => commands.debug(),
            KanidmClientOpt::Person { commands } => commands.debug(),
            KanidmClientOpt::ServiceAccount { commands } => commands.debug(),
            KanidmClientOpt::System { commands } => commands.debug(),
            KanidmClientOpt::Recycle { commands } => commands.debug(),
            KanidmClientOpt::Version {} => {
                println!("kanidm {}", env!("KANIDM_PKG_VERSION"));
                true
            }
        }
    }

    pub async fn exec(&self) {
        match self {
            KanidmClientOpt::Raw { commands } => commands.exec().await,
            KanidmClientOpt::Login(lopt) => lopt.exec().await,
            KanidmClientOpt::Reauth(lopt) => lopt.exec().await,
            KanidmClientOpt::Logout(lopt) => lopt.exec().await,
            KanidmClientOpt::Session { commands } => commands.exec().await,
            KanidmClientOpt::CSelf { commands } => commands.exec().await,
            KanidmClientOpt::Person { commands } => commands.exec().await,
            KanidmClientOpt::ServiceAccount { commands } => commands.exec().await,
            KanidmClientOpt::Group { commands } => commands.exec().await,
            KanidmClientOpt::System { commands } => commands.exec().await,
            KanidmClientOpt::Recycle { commands } => commands.exec().await,
            KanidmClientOpt::Version {} => (),
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

// TODO: this regex is also used in the webui (https://github.com/kanidm/kanidm/blob/003234c2d0a52146683628156e2a106bf61fe9f4/server/web_ui/src/views/identityverification.rs#L60) should we move it to proto?

lazy_static::lazy_static! {
    pub static ref VALIDATE_TOTP_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new(r"^\d{6}$").expect("Invalid singleline regex found")
    };
}

enum IdentifyUserState {
    Start,
    IdDisplayAndSubmit,
    SubmitCode,
    DisplayCodeFirst { self_totp: u32, step: u32 },
    DisplayCodeSecond { self_totp: u32, step: u32 },
    ConfirmCodeVerifiedFirst,
    ConfirmCodeVerifiedSecond,
}

/// This is the identity verification feature handler
#[async_recursion] // dear lord have mercy for I have sinned writing this function
async fn identify_user_exec<'a>(
    state: IdentifyUserState,
    client: KanidmClient,
    self_id: &'a str,
    other_id: Option<&'a str>,
) {
    match state {
        IdentifyUserState::Start => {
            let res = match client
                .idm_person_identify_user(self_id, IdentifyUserRequest::Start)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                    println!("Exiting...");
                    return;
                }
            };
            match res {
                IdentifyUserResponse::IdentityVerificationUnavailable => {
                    println!("Identity verification is not available for this user");
                    return;
                }
                IdentifyUserResponse::IdentityVerificationAvailable => {
                    identify_user_exec(
                        IdentifyUserState::IdDisplayAndSubmit,
                        client,
                        self_id,
                        other_id,
                    )
                    .await
                }
                _ => {
                    eprintln!("Invalid response from server. Exiting...");
                    return;
                }
            }
        }
        IdentifyUserState::IdDisplayAndSubmit => {
            println!("When asked for your ID, provide the following: {self_id}");

            // Display Prompt
            let other_user_id: String = Input::new()
                .with_prompt("\nAsk for the other person's ID, and insert it here")
                .interact_text()
                .expect("Failed to interact with interactive session");
            let _ = stdout().flush();

            let res = match client
                .idm_person_identify_user(&other_user_id, IdentifyUserRequest::Start)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                    println!("Exiting...");
                    return;
                }
            };
            match res {
                IdentifyUserResponse::WaitForCode => {
                    identify_user_exec(
                        IdentifyUserState::SubmitCode,
                        client,
                        self_id,
                        Some(&other_user_id),
                    )
                    .await
                }
                IdentifyUserResponse::ProvideCode { step, totp } => {
                    identify_user_exec(
                        IdentifyUserState::DisplayCodeFirst {
                            self_totp: totp,
                            step,
                        },
                        client,
                        self_id,
                        Some(&other_user_id),
                    )
                    .await
                }
                IdentifyUserResponse::InvalidUserId => {
                    eprintln!(
                        "{other_user_id} cannot use the identity verification feature. Exiting..."
                    );
                    return;
                }
                _ => {
                    eprintln!("Invalid response from server. Exiting...");
                    return;
                }
            }
        }
        IdentifyUserState::SubmitCode => {
            // Display Prompt
            let other_totp: String = Input::new()
                .with_prompt("\nInsert here the other person code")
                .validate_with(|s: &String| -> Result<(), &str> {
                    if VALIDATE_TOTP_RE.is_match(s) {
                        Ok(())
                    } else {
                        Err("Invalid code format")
                    }
                })
                .interact_text()
                .expect("Failed to interact with interactive session");

            let res = match client
                .idm_person_identify_user(
                    &other_id.unwrap_or_default(),
                    IdentifyUserRequest::SubmitCode {
                        other_totp: other_totp.parse().unwrap_or_default(),
                    },
                )
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                    println!("Exiting...");
                    return;
                }
            };
            match res {
                IdentifyUserResponse::CodeFailure => {
                    eprintln!(
                        "The provided code doesn't belong to {}. Exiting...",
                        other_id.unwrap_or_default()
                    );
                    return;
                }
                IdentifyUserResponse::Success => {
                    println!(
                        "{}'s identity has been successfully verified",
                        other_id.unwrap_or_default()
                    );
                    return;
                }
                IdentifyUserResponse::InvalidUserId => {
                    eprintln!(
                        "{} cannot use the identity verification feature. Exiting...",
                        other_id.unwrap_or_default()
                    );
                    return;
                }
                IdentifyUserResponse::ProvideCode { step, totp } => {
                    identify_user_exec(
                        // since we have already inserted the code, we have to go to display code second,
                        IdentifyUserState::DisplayCodeSecond {
                            self_totp: totp,
                            step,
                        },
                        client,
                        self_id,
                        other_id,
                    )
                    .await
                }

                _ => {
                    eprintln!("Invalid response from server. Exiting...");
                    return;
                }
            }
        }
        IdentifyUserState::DisplayCodeFirst { self_totp, step } => {
            println!("\r\rProvide the following code when asked: {}", self_totp);
            let _ = stdout().flush();
            let join = task::spawn(async move {
                // let theme = ColorfulTheme::default();
                // let proceed = Confirm::with_theme(&theme)
                //     .with_prompt("Did you confirm the other user successfully verified your code?")
                //     .interact_on(&Term::stderr())
                //     .unwrap();
                let mut stdin = InteractiveStdin::new();
                let res = stdin.next_line().await;
                dbg!(res);
            });
            print_ticks(step).await;
            // print_ticks(step).await;
            join.await.unwrap();

            let res = match client
                .idm_person_identify_user(
                    &other_id.unwrap_or_default(),
                    IdentifyUserRequest::DisplayCode,
                )
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                    println!("Exiting...");
                    return;
                }
            };
            let IdentifyUserResponse::ProvideCode { step, totp } = res else {
                eprintln!("Invalid response from server. Exiting...");
                return;
            };
            identify_user_exec(
                IdentifyUserState::DisplayCodeFirst {
                    self_totp: totp,
                    step,
                },
                client,
                self_id,
                other_id,
            )
            .await;
        }
        IdentifyUserState::DisplayCodeSecond { self_totp, step } => {}
        IdentifyUserState::ConfirmCodeVerifiedFirst => {}
        IdentifyUserState::ConfirmCodeVerifiedSecond => {}
    }
}

// TODO: this function is somewhat a duplicate of what can be found in the webui, see https://github.com/kanidm/kanidm/blob/003234c2d0a52146683628156e2a106bf61fe9f4/server/web_ui/src/components/totpdisplay.rs#L83
// * should we move it to a common crate or can we just leave it there?
fn get_time_left_from_now(step: u128) -> u32 {
    #[allow(clippy::expect_used)]
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("invalid duration from epoch now");
    let secs: u128 = dur.as_millis();
    (step * 1000 - secs % (step * 1000)) as u32
}

async fn print_ticks(step: u32) {
    let time_left = get_time_left_from_now(step as u128);
    let stdin = stdin();
    let time_left_ms = time_left % 1000;
    let mut ticks_left = ((time_left - time_left_ms) / 1000) as i32 + 1;
    let mut sync_interval = interval(Duration::from_millis(time_left_ms as u64));

    sync_interval.tick().await;
    // wait for us to be synched to the second
    let mut interval = interval(Duration::from_secs(1));
    while ticks_left >= 0 {
        print!("\rtime left: {ticks_left}s");
        let _ = stdout().flush();
        interval.tick().await;
        ticks_left -= 1;
    }
    let _ = stdout().flush(); // we wait another second so the next function call
                              // will never have a `ticks_left` == 0
}

use tokio::sync::mpsc;

struct InteractiveStdin {
    chan: mpsc::Receiver<std::io::Result<String>>,
}

impl InteractiveStdin {
    fn new() -> Self {
        let (send, recv) = mpsc::channel(16);
        std::thread::spawn(move || {
            for line in std::io::stdin().lines() {
                if send.blocking_send(line).is_err() {
                    return;
                }
            }
        });
        InteractiveStdin { chan: recv }
    }

    /// Get the next line from stdin.
    ///
    /// Returns `Ok(None)` if stdin has been closed.
    ///
    /// This method is cancel safe.
    async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        self.chan.recv().await.transpose()
    }
}
