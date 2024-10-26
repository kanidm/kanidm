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
#[macro_use]
extern crate tracing;

use crate::common::OpType;
use std::path::PathBuf;

use identify_user_no_tui::{run_identity_verification_no_tui, IdentifyUserState};

use kanidm_client::{ClientError, StatusCode};
use url::Url;
use uuid::Uuid;

include!("../opt/kanidm.rs");

mod common;
mod domain;
mod graph;
mod group;
mod oauth2;
mod person;
mod raw;
mod recycle;
mod serviceaccount;
mod session;
mod synch;
mod system_config;
mod webauthn;

/// Throws an error and exits the program when we get an error
pub(crate) fn handle_client_error(response: ClientError, _output_mode: OutputMode) {
    match response {
        ClientError::Http(status, error, opid) => {
            let error_msg = match error {
                Some(msg) => format!(" {:?}", msg),
                None => "".to_string(),
            };
            error!("OperationId: {:?}", opid);
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                error!("Internal Server Error in response: {}", error_msg);
                std::process::exit(1);
            } else if status == StatusCode::NOT_FOUND {
                error!("Item not found: Check all names are correct.");
            } else {
                error!("HTTP Error: {}{}", status, error_msg);
            }
        }
        ClientError::Transport(e) => {
            error!("HTTP-Transport Related Error: {:?}", e);
            std::process::exit(1);
        }
        ClientError::UntrustedCertificate(e) => {
            error!("Untrusted Certificate Error: {:?}", e);
            std::process::exit(1);
        }
        _ => {
            eprintln!("{:?}", response);
        }
    };
}

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
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SelfOpt::IdentifyUser(copt) => {
                let client = copt.to_client(OpType::Write).await;
                let whoami_response = match client.whoami().await {
                    Ok(o_ent) => {
                        match o_ent {
                            Some(ent) => ent,
                            None => {
                                eprintln!("Authentication with cached token failed, can't query information."); // TODO: add an error ID (login, or clear token cache)
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error querying whoami endpoint: {:?}", e); // TODO: add an error ID (internal/web response error, restart or check connectivity)
                        return;
                    }
                };

                let spn =
                    match whoami_response.attrs.get("spn").and_then(|v| v.first()) {
                        Some(spn) => spn,
                        None => {
                            eprintln!("Failed to parse your SPN from the system's whoami endpoint, exiting!"); // TODO: add an error ID (internal/web response error, restart)
                            return;
                        }
                    };

                run_identity_verification_no_tui(IdentifyUserState::Start, client, spn, None).await;
            } // end PersonOpt::Validity
        }
    }
}

impl SystemOpt {
    pub fn debug(&self) -> bool {
        match self {
            SystemOpt::Api { commands } => commands.debug(),
            SystemOpt::PwBadlist { commands } => commands.debug(),
            SystemOpt::DeniedNames { commands } => commands.debug(),
            SystemOpt::Oauth2 { commands } => commands.debug(),
            SystemOpt::Domain { commands } => commands.debug(),
            SystemOpt::Synch { commands } => commands.debug(),
        }
    }

    pub async fn exec(&self) {
        match self {
            SystemOpt::Api { commands } => commands.exec().await,
            SystemOpt::PwBadlist { commands } => commands.exec().await,
            SystemOpt::DeniedNames { commands } => commands.exec().await,
            SystemOpt::Oauth2 { commands } => commands.exec().await,
            SystemOpt::Domain { commands } => commands.exec().await,
            SystemOpt::Synch { commands } => commands.exec().await,
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
            KanidmClientOpt::Graph(gopt) => gopt.debug(),
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
            KanidmClientOpt::Graph(gops) => gops.exec().await,
            KanidmClientOpt::System { commands } => commands.exec().await,
            KanidmClientOpt::Recycle { commands } => commands.exec().await,
            KanidmClientOpt::Version {} => (),
        }
    }
}

pub(crate) fn password_prompt(prompt: &str) -> Option<String> {
    for _ in 0..3 {
        let password = dialoguer::Password::new()
            .with_prompt(prompt)
            .interact()
            .ok()?;

        let password_confirm = dialoguer::Password::new()
            .with_prompt("Reenter the password to confirm: ")
            .interact()
            .ok()?;

        if password == password_confirm {
            return Some(password);
        } else {
            error!("Passwords do not match");
        }
    }
    None
}

pub const IDENTITY_UNAVAILABLE_ERROR_MESSAGE: &str = "The identity verification feature is not enabled for your account, please contact an administrator.";
pub const CODE_FAILURE_ERROR_MESSAGE: &str = "The provided code doesn't match, please try again.";
pub const INVALID_USER_ID_ERROR_MESSAGE: &str =
    "account exists but cannot access the identity verification feature 😕";
pub const INVALID_STATE_ERROR_MESSAGE: &str =
    "The user identification flow is in an invalid state 😵😵";

mod identify_user_no_tui {
    use crate::{
        CODE_FAILURE_ERROR_MESSAGE, IDENTITY_UNAVAILABLE_ERROR_MESSAGE,
        INVALID_STATE_ERROR_MESSAGE, INVALID_USER_ID_ERROR_MESSAGE,
    };

    use kanidm_client::{ClientError, KanidmClient};
    use kanidm_proto::internal::{IdentifyUserRequest, IdentifyUserResponse};

    use dialoguer::{Confirm, Input};
    use regex::Regex;
    use std::{
        io::{stdout, Write},
        time::SystemTime,
    };

    lazy_static::lazy_static! {
        pub static ref VALIDATE_TOTP_RE: Regex = {
            #[allow(clippy::expect_used)]
            Regex::new(r"^\d{5,6}$").expect("Failed to parse VALIDATE_TOTP_RE") // TODO: add an error ID (internal error, restart)
        };
    }

    pub(super) enum IdentifyUserState {
        Start,
        IdDisplayAndSubmit,
        SubmitCode,
        DisplayCodeFirst { self_totp: u32, step: u32 },
        DisplayCodeSecond { self_totp: u32, step: u32 },
    }

    fn server_error(e: &ClientError) {
        eprintln!("Server error!"); // TODO: add an error ID (internal error, restart)
        eprintln!("{:?}", e);
        println!("Exiting...");
    }

    pub(super) async fn run_identity_verification_no_tui(
        mut state: IdentifyUserState,
        client: KanidmClient,
        self_id: &str,
        mut other_id: Option<String>,
    ) {
        loop {
            match state {
                IdentifyUserState::Start => {
                    let res = match &client
                        .idm_person_identify_user(self_id, IdentifyUserRequest::Start)
                        .await
                    {
                        Ok(res) => res.clone(),
                        Err(e) => {
                            return server_error(e);
                        }
                    };
                    match res {
                        IdentifyUserResponse::IdentityVerificationUnavailable => {
                            println!("{IDENTITY_UNAVAILABLE_ERROR_MESSAGE}");
                            return;
                        }
                        IdentifyUserResponse::IdentityVerificationAvailable => {
                            state = IdentifyUserState::IdDisplayAndSubmit;
                        }
                        _ => {
                            eprintln!("{INVALID_STATE_ERROR_MESSAGE}");
                            return;
                        }
                    }
                }
                IdentifyUserState::IdDisplayAndSubmit => {
                    println!("When asked for your ID, provide the following: {self_id}");

                    // Display Prompt
                    let other_user_id: String = Input::new()
                        .with_prompt("Ask for the other person's ID, and insert it here")
                        .interact_text()
                        .expect("Failed to interact with interactive session");
                    let _ = stdout().flush();

                    let res = match &client
                        .idm_person_identify_user(&other_user_id, IdentifyUserRequest::Start)
                        .await
                    {
                        Ok(res) => res.clone(),
                        Err(e) => {
                            return server_error(e);
                        }
                    };
                    match res {
                        IdentifyUserResponse::WaitForCode => {
                            state = IdentifyUserState::SubmitCode;

                            other_id = Some(other_user_id);
                        }
                        IdentifyUserResponse::ProvideCode { step, totp } => {
                            state = IdentifyUserState::DisplayCodeFirst {
                                self_totp: totp,
                                step,
                            };

                            other_id = Some(other_user_id);
                        }
                        IdentifyUserResponse::InvalidUserId => {
                            eprintln!("{other_user_id} {INVALID_USER_ID_ERROR_MESSAGE}");
                            return;
                        }
                        _ => {
                            eprintln!("{INVALID_STATE_ERROR_MESSAGE}");
                            return;
                        }
                    }
                }
                IdentifyUserState::SubmitCode => {
                    // Display Prompt
                    let other_totp: String = Input::new()
                        .with_prompt("Insert here the other person code")
                        .validate_with(|s: &String| -> Result<(), &str> {
                            if VALIDATE_TOTP_RE.is_match(s) {
                                Ok(())
                            } else {
                                Err("The code should be a 5 or 6 digit number")
                            }
                        })
                        .interact_text()
                        .expect("Failed to interact with interactive session");

                    let res = match &client
                        .idm_person_identify_user(
                            other_id.as_deref().unwrap_or_default(),
                            IdentifyUserRequest::SubmitCode {
                                other_totp: other_totp.parse().unwrap_or_default(),
                            },
                        )
                        .await
                    {
                        Ok(res) => res.clone(),
                        Err(e) => {
                            return server_error(e);
                        }
                    };
                    match res {
                        IdentifyUserResponse::CodeFailure => {
                            eprintln!("{CODE_FAILURE_ERROR_MESSAGE}");
                            return;
                        }
                        IdentifyUserResponse::Success => {
                            println!(
                                "{}'s identity has been successfully verified 🎉🎉",
                                other_id.as_deref().unwrap_or_default()
                            );
                            return;
                        }
                        IdentifyUserResponse::InvalidUserId => {
                            eprintln!(
                                "{} {INVALID_USER_ID_ERROR_MESSAGE}",
                                other_id.as_deref().unwrap_or_default()
                            );
                            return;
                        }
                        IdentifyUserResponse::ProvideCode { step, totp } => {
                            // since we have already inserted the code, we have to go to display code second,
                            state = IdentifyUserState::DisplayCodeSecond {
                                self_totp: totp,
                                step,
                            };
                        }

                        _ => {
                            eprintln!("{INVALID_STATE_ERROR_MESSAGE}");
                            return;
                        }
                    }
                }
                IdentifyUserState::DisplayCodeFirst { self_totp, step } => {
                    println!("Provide the following code when asked: {}", self_totp);
                    let seconds_left = get_ms_left_from_now(step as u128) / 1000;
                    println!("This codes expires in {seconds_left} seconds");
                    let _ = stdout().flush();
                    if !matches!(Confirm::new().with_prompt("Continue?").interact(), Ok(true)) {
                        println!("Identity verification failed. Exiting...");
                        return;
                    }
                    match Confirm::new()
                    .with_prompt(format!("Did you confirm that {} correctly verified your code? If you proceed, you won't be able to go back.", other_id.as_deref().unwrap_or_default()))
                    .interact() {
                        Ok(true) => {println!("Code confirmed, continuing...")}
                        Ok(false) => {
                            println!("Identity verification failed. Exiting...");
                            return;
                        },
                        Err(e) => {
                            eprintln!("An error occurred while trying to read from stderr: {:?}", e); // TODO: add error ID (internal error, restart)
                            println!("Exiting...");
                            return;
                        },
                        };

                    state = IdentifyUserState::SubmitCode;
                }
                IdentifyUserState::DisplayCodeSecond { self_totp, step } => {
                    println!("Provide the following code when asked: {}", self_totp);
                    let seconds_left = get_ms_left_from_now(step as u128) / 1000;
                    println!("This codes expires in {seconds_left} seconds!");
                    let _ = stdout().flush();
                    if !matches!(Confirm::new().with_prompt("Continue?").interact(), Ok(true)) {
                        println!("Identity verification failed. Exiting...");
                        return;
                    }
                    match Confirm::new()
                    .with_prompt(format!("Did you confirm that {} correctly verified your code? If you proceed, you won't be able to go back.", other_id.as_deref().unwrap_or_default()))
                    .interact() {
                        Ok(true) => {println!(
                            "{}'s identity has been successfully verified 🎉🎉",
                            other_id.take().unwrap_or_default()
                        );
                        return;}
                        Ok(false) => {
                            println!("Exiting...");
                            return;
                        },
                        Err(e) => {
                            eprintln!("An error occurred while trying to read from stderr: {:?}", e); // TODO: add error ID (internal error, restart)
                            println!("Exiting...");
                            return;
                        },
                        };
                }
            }
        }
    }

    // TODO: this function is somewhat a duplicate of what can be found in the webui, see https://github.com/kanidm/kanidm/blob/003234c2d0a52146683628156e2a106bf61fe9f4/server/web_ui/src/components/totpdisplay.rs#L83
    // * should we move it to a common crate or can we just leave it there?
    fn get_ms_left_from_now(step: u128) -> u32 {
        #[allow(clippy::expect_used)]
        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("invalid duration from epoch now");
        let ms: u128 = dur.as_millis();
        (step * 1000 - ms % (step * 1000)) as u32
    }
}
