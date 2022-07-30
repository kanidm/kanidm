use crate::password_prompt;
use crate::{
    AccountCredential, AccountOpt, AccountPerson, AccountPosix, AccountRadius, AccountSsh,
    AccountValidity,
};
use dialoguer::{theme::ColorfulTheme, Select};
use dialoguer::{Confirm, Input, Password};
use kanidm_client::ClientError::Http as ClientErrorHttp;
use kanidm_client::KanidmClient;
use kanidm_proto::messages::{AccountChangeMessage, ConsoleOutputMode, MessageStatus};
use kanidm_proto::v1::OperationError::{InvalidAttribute, PasswordQuality};
use kanidm_proto::v1::{CUIntentToken, CURegState, CUSessionToken, CUStatus, TotpSecret};
use qrcode::{render::unicode, QrCode};
use std::fmt::{self, Debug};
use std::str::FromStr;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use webauthn_authenticator_rs::{u2fhid::U2FHid, WebauthnAuthenticator};

impl AccountOpt {
    pub fn debug(&self) -> bool {
        match self {
            AccountOpt::Credential { commands } => commands.debug(),
            AccountOpt::Radius { commands } => match commands {
                AccountRadius::Show(aro) => aro.copt.debug,
                AccountRadius::Generate(aro) => aro.copt.debug,
                AccountRadius::DeleteSecret(aro) => aro.copt.debug,
            },
            AccountOpt::Posix { commands } => match commands {
                AccountPosix::Show(apo) => apo.copt.debug,
                AccountPosix::Set(apo) => apo.copt.debug,
                AccountPosix::SetPassword(apo) => apo.copt.debug,
            },
            AccountOpt::Person { commands } => match commands {
                AccountPerson::Extend(apo) => apo.copt.debug,
                AccountPerson::Set(apo) => apo.copt.debug,
            },
            AccountOpt::Ssh { commands } => match commands {
                AccountSsh::List(ano) => ano.copt.debug,
                AccountSsh::Add(ano) => ano.copt.debug,
                AccountSsh::Delete(ano) => ano.copt.debug,
            },
            AccountOpt::List(copt) => copt.debug,
            AccountOpt::Get(aopt) => aopt.copt.debug,
            AccountOpt::Delete(aopt) => aopt.copt.debug,
            AccountOpt::Create(aopt) => aopt.copt.debug,
            AccountOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => ano.copt.debug,
                AccountValidity::ExpireAt(ano) => ano.copt.debug,
                AccountValidity::BeginFrom(ano) => ano.copt.debug,
            },
        }
    }

    pub async fn exec(&self) {
        match self {
            // id/cred/primary/set
            AccountOpt::Credential { commands } => commands.exec().await,
            AccountOpt::Radius { commands } => match commands {
                AccountRadius::Show(aopt) => {
                    let client = aopt.copt.to_client().await;

                    let rcred = client
                        .idm_account_radius_credential_get(aopt.aopts.account_id.as_str())
                        .await;

                    match rcred {
                        Ok(Some(s)) => println!(
                            "RADIUS secret for {}: {}",
                            aopt.aopts.account_id.as_str(),
                            s,
                        ),
                        Ok(None) => println!(
                            "No RADIUS secret set for user {}",
                            aopt.aopts.account_id.as_str(),
                        ),
                        Err(e) => {
                            error!("Error -> {:?}", e);
                        }
                    }
                }
                AccountRadius::Generate(aopt) => {
                    let client = aopt.copt.to_client().await;
                    if let Err(e) = client
                        .idm_account_radius_credential_regenerate(aopt.aopts.account_id.as_str())
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
                AccountRadius::DeleteSecret(aopt) => {
                    let client = aopt.copt.to_client().await;
                    let mut modmessage = AccountChangeMessage {
                        output_mode: ConsoleOutputMode::Text,
                        action: "radius account_delete".to_string(),
                        result: "deleted".to_string(),
                        src_user: aopt
                            .copt
                            .username
                            .to_owned()
                            .unwrap_or(format!("{:?}", client.whoami().await)),
                        dest_user: aopt.aopts.account_id.to_string(),
                        status: MessageStatus::Success,
                    };
                    match client
                        .idm_account_radius_credential_delete(aopt.aopts.account_id.as_str())
                        .await
                    {
                        Err(e) => {
                            modmessage.status = MessageStatus::Failure;
                            modmessage.result = format!("Error -> {:?}", e);
                            error!("{}", modmessage);
                        }
                        Ok(result) => {
                            debug!("{:?}", result);
                            println!("{}", modmessage);
                        }
                    };
                }
            }, // end AccountOpt::Radius
            AccountOpt::Posix { commands } => match commands {
                AccountPosix::Show(aopt) => {
                    let client = aopt.copt.to_client().await;
                    match client
                        .idm_account_unix_token_get(aopt.aopts.account_id.as_str())
                        .await
                    {
                        Ok(token) => println!("{}", token),
                        Err(e) => {
                            error!("Error -> {:?}", e);
                        }
                    }
                }
                AccountPosix::Set(aopt) => {
                    let client = aopt.copt.to_client().await;
                    if let Err(e) = client
                        .idm_account_unix_extend(
                            aopt.aopts.account_id.as_str(),
                            aopt.gidnumber,
                            aopt.shell.as_deref(),
                        )
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
                AccountPosix::SetPassword(aopt) => {
                    let client = aopt.copt.to_client().await;
                    let password = match password_prompt("Enter new posix (sudo) password: ") {
                        Some(v) => v,
                        None => {
                            println!("Passwords do not match");
                            return;
                        }
                    };

                    if let Err(e) = client
                        .idm_account_unix_cred_put(
                            aopt.aopts.account_id.as_str(),
                            password.as_str(),
                        )
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
            }, // end AccountOpt::Posix

            AccountOpt::Person { commands } => match commands {
                AccountPerson::Extend(aopt) => {
                    let client = aopt.copt.to_client().await;
                    let mut result_output = kanidm_proto::messages::AccountChangeMessage {
                        output_mode: ConsoleOutputMode::Text,
                        action: String::from("account_person_extend"),
                        result: String::from("This is a filler message"),
                        src_user: aopt
                            .copt
                            .username
                            .to_owned()
                            .unwrap_or(format!("{:?}", client.whoami().await)),
                        dest_user: aopt.aopts.account_id.to_string(),
                        status: kanidm_proto::messages::MessageStatus::Failure,
                    };
                    match client
                        .idm_account_person_extend(
                            aopt.aopts.account_id.as_str(),
                            aopt.mail.as_deref(),
                            aopt.legalname.as_deref(),
                        )
                        .await
                    {
                        // TODO: JSON output for account person extend.
                        Ok(_) => {
                            result_output.status = kanidm_proto::messages::MessageStatus::Success;
                            result_output.result = format!(
                                "Successfully extended the user {}.",
                                aopt.aopts.account_id
                            );
                            match &aopt.legalname {
                                Some(legalname) => {
                                    result_output.result +=
                                        format!(" Set legalname to {}.", legalname).as_str()
                                }
                                _ => debug!("Didn't change legalname field."),
                            };
                            match &aopt.mail {
                                Some(mail) => {
                                    result_output.result +=
                                        format!(" Set mail to {:?}.", mail.join(", ")).as_str()
                                }
                                _ => debug!("Didn't change mail field."),
                            };
                            println!("{}", result_output);
                        }
                        // TODO: consider a macro to unpack the KanidmClient result object
                        Err(e) => {
                            match e {
                                ClientErrorHttp(_, result, _) => {
                                    if let Some(ia_error) = result {
                                        match ia_error {
                                            InvalidAttribute(msg) => {
                                                result_output.result =
                                                    format!("Failed to set value: {}", msg)
                                            }
                                            _ => {
                                                result_output.result =
                                                    format!("Operation Error - {:?}", ia_error)
                                            }
                                        };
                                    } else {
                                        result_output.result =
                                            format!("ClientError - {:?}", result);
                                    }
                                }
                                _ => result_output.result = format!("Error -> {:?}", e),
                            };
                            eprintln!("{:?}", result_output);
                        }
                    }
                }

                // TODO: there should probably be an 'unset' variant of this
                AccountPerson::Set(aopt) => {
                    let client = aopt.copt.to_client().await;
                    let mut result_output = AccountChangeMessage {
                        output_mode: ConsoleOutputMode::Text,
                        action: String::from("account_person set"),
                        result: String::from(""),
                        src_user: aopt
                            .copt
                            .username
                            .to_owned()
                            .unwrap_or(format!("{:?}", client.whoami().await)),
                        dest_user: aopt.aopts.account_id.to_string(),
                        status: MessageStatus::Failure,
                    };
                    match client
                        .idm_account_person_set(
                            aopt.aopts.account_id.as_str(),
                            aopt.mail.as_deref(),
                            aopt.legalname.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => {
                            result_output.status = kanidm_proto::messages::MessageStatus::Success;
                            result_output.result = "set 'person' status on user".to_string();
                            println!("{}", result_output)
                        }
                        // TODO: ponder macro'ing handling ClientError
                        Err(e) => {
                            result_output.result = format!("Error -> {:?}", e);
                            eprintln!("{}", result_output)
                        }
                    }
                }
            }, // end AccountOpt::Person
            AccountOpt::Ssh { commands } => match commands {
                AccountSsh::List(aopt) => {
                    let client = aopt.copt.to_client().await;

                    match client
                        .idm_account_get_ssh_pubkeys(aopt.aopts.account_id.as_str())
                        .await
                    {
                        Ok(pkeys) => pkeys.iter().for_each(|pkey| println!("{}", pkey)),
                        Err(e) => {
                            error!("Error -> {:?}", e);
                        }
                    }
                }
                AccountSsh::Add(aopt) => {
                    let client = aopt.copt.to_client().await;
                    if let Err(e) = client
                        .idm_account_post_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                            aopt.pubkey.as_str(),
                        )
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
                AccountSsh::Delete(aopt) => {
                    let client = aopt.copt.to_client().await;
                    if let Err(e) = client
                        .idm_account_delete_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                        )
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
            }, // end AccountOpt::Ssh
            AccountOpt::List(copt) => {
                let client = copt.to_client().await;
                match client.idm_account_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            AccountOpt::Get(aopt) => {
                let client = aopt.copt.to_client().await;
                match client.idm_account_get(aopt.aopts.account_id.as_str()).await {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            AccountOpt::Delete(aopt) => {
                let client = aopt.copt.to_client().await;
                let mut modmessage = AccountChangeMessage {
                    output_mode: ConsoleOutputMode::Text,
                    action: "account delete".to_string(),
                    result: "deleted".to_string(),
                    src_user: aopt
                        .copt
                        .username
                        .to_owned()
                        .unwrap_or(format!("{:?}", client.whoami().await)),
                    dest_user: aopt.aopts.account_id.to_string(),
                    status: MessageStatus::Success,
                };
                match client
                    .idm_account_delete(aopt.aopts.account_id.as_str())
                    .await
                {
                    Err(e) => {
                        modmessage.result = format!("Error -> {:?}", e);
                        modmessage.status = MessageStatus::Failure;
                        eprintln!("{}", modmessage);
                    }
                    Ok(result) => {
                        debug!("{:?}", result);
                        println!("{}", modmessage);
                    }
                };
            }
            AccountOpt::Create(acopt) => {
                let client = acopt.copt.to_client().await;
                if let Err(e) = client
                    .idm_account_create(
                        acopt.aopts.account_id.as_str(),
                        acopt.display_name.as_str(),
                    )
                    .await
                {
                    error!("Error -> {:?}", e)
                }
            }
            AccountOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => {
                    let client = ano.copt.to_client().await;

                    println!("user: {}", ano.aopts.account_id.as_str());
                    let ex = match client
                        .idm_account_get_attr(ano.aopts.account_id.as_str(), "account_expire")
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Error -> {:?}", e);
                            return;
                        }
                    };

                    let vf = match client
                        .idm_account_get_attr(ano.aopts.account_id.as_str(), "account_valid_from")
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Error -> {:?}", e);
                            return;
                        }
                    };

                    if let Some(t) = vf {
                        // Convert the time to local timezone.
                        let t = OffsetDateTime::parse(&t[0], time::Format::Rfc3339)
                            .map(|odt| {
                                odt.to_offset(
                                    time::UtcOffset::try_current_local_offset()
                                        .unwrap_or(time::UtcOffset::UTC),
                                )
                                .format(time::Format::Rfc3339)
                            })
                            .unwrap_or_else(|_| "invalid timestamp".to_string());

                        println!("valid after: {}", t);
                    } else {
                        println!("valid after: any time");
                    }

                    if let Some(t) = ex {
                        let t = OffsetDateTime::parse(&t[0], time::Format::Rfc3339)
                            .map(|odt| {
                                odt.to_offset(
                                    time::UtcOffset::try_current_local_offset()
                                        .unwrap_or(time::UtcOffset::UTC),
                                )
                                .format(time::Format::Rfc3339)
                            })
                            .unwrap_or_else(|_| "invalid timestamp".to_string());
                        println!("expire: {}", t);
                    } else {
                        println!("expire: never");
                    }
                }
                AccountValidity::ExpireAt(ano) => {
                    let client = ano.copt.to_client().await;
                    if matches!(ano.datetime.as_str(), "never" | "clear") {
                        // Unset the value
                        match client
                            .idm_account_purge_attr(ano.aopts.account_id.as_str(), "account_expire")
                            .await
                        {
                            Err(e) => error!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    } else {
                        if let Err(e) =
                            OffsetDateTime::parse(ano.datetime.as_str(), time::Format::Rfc3339)
                        {
                            error!("Error -> {:?}", e);
                            return;
                        }

                        match client
                            .idm_account_set_attr(
                                ano.aopts.account_id.as_str(),
                                "account_expire",
                                &[ano.datetime.as_str()],
                            )
                            .await
                        {
                            Err(e) => error!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    }
                }
                AccountValidity::BeginFrom(ano) => {
                    let client = ano.copt.to_client().await;
                    if matches!(ano.datetime.as_str(), "any" | "clear" | "whenever") {
                        // Unset the value
                        match client
                            .idm_account_purge_attr(
                                ano.aopts.account_id.as_str(),
                                "account_valid_from",
                            )
                            .await
                        {
                            Err(e) => error!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    } else {
                        // Attempt to parse and set
                        if let Err(e) =
                            OffsetDateTime::parse(ano.datetime.as_str(), time::Format::Rfc3339)
                        {
                            error!("Error -> {:?}", e);
                            return;
                        }

                        match client
                            .idm_account_set_attr(
                                ano.aopts.account_id.as_str(),
                                "account_valid_from",
                                &[ano.datetime.as_str()],
                            )
                            .await
                        {
                            Err(e) => error!("Error -> {:?}", e),
                            _ => println!("Success"),
                        }
                    }
                }
            }, // end AccountOpt::Validity
        }
    }
}

impl AccountCredential {
    pub fn debug(&self) -> bool {
        match self {
            AccountCredential::CreateResetToken(aopt) => aopt.copt.debug,
            AccountCredential::UseResetToken(aopt) => aopt.copt.debug,
            AccountCredential::Update(aopt) => aopt.copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            AccountCredential::Update(aopt) => {
                let client = aopt.copt.to_client().await;
                match client
                    .idm_account_credential_update_begin(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok((cusession_token, custatus)) => {
                        credential_update_exec(cusession_token, custatus, client).await
                    }
                    Err(e) => {
                        error!("Error starting credential update -> {:?}", e);
                    }
                }
            }
            // The account credential use_reset_token CLI
            AccountCredential::UseResetToken(aopt) => {
                let client = aopt.copt.to_unauth_client();
                let cuintent_token = CUIntentToken {
                    token: aopt.token.clone(),
                };

                match client
                    .idm_account_credential_update_exchange(cuintent_token)
                    .await
                {
                    Ok((cusession_token, custatus)) => {
                        credential_update_exec(cusession_token, custatus, client).await
                    }
                    Err(e) => {
                        match e {
                            ClientErrorHttp(status_code, error, _kopid) => {
                                eprintln!(
                                    "Error completing command: HTTP{} - {:?}",
                                    status_code,
                                    error.unwrap()
                                );
                            }
                            _ => error!("Error starting use_reset_token -> {:?}", e),
                        };
                    }
                }
            }
            AccountCredential::CreateResetToken(aopt) => {
                let client = aopt.copt.to_client().await;

                // What's the client url?
                match client
                    .idm_account_credential_update_intent(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok(cuintent_token) => {
                        let mut url = Url::parse(client.get_url()).expect("Invalid server url.");
                        url.set_path("/ui/reset");
                        url.query_pairs_mut()
                            .append_pair("token", cuintent_token.token.as_str());

                        debug!(
                            "Successfully created credential reset token for {}: {}",
                            aopt.aopts.account_id, cuintent_token.token
                        );
                        println!(
                            "The person can use one of the following to allow the credential reset"
                        );
                        println!("\nScan this QR Code:\n");
                        let code = match QrCode::new(url.as_str()) {
                            Ok(c) => c,
                            Err(e) => {
                                error!("Failed to generate QR code -> {:?}", e);
                                return;
                            }
                        };
                        let image = code
                            .render::<unicode::Dense1x2>()
                            .dark_color(unicode::Dense1x2::Light)
                            .light_color(unicode::Dense1x2::Dark)
                            .build();
                        println!("{}", image);

                        println!();
                        println!("This link: {}", url.as_str());
                        println!(
                            "Or run this command: kanidm account credential use_reset_token {}",
                            cuintent_token.token
                        );
                        println!();
                    }
                    Err(e) => {
                        error!("Error starting credential reset -> {:?}", e);
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum CUAction {
    Help,
    Status,
    Password,
    Totp,
    TotpRemove,
    BackupCodes,
    Remove,
    Passkey,
    PasskeyRemove,
    End,
    Commit,
}

impl fmt::Display for CUAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"
help (h, ?) - Display this help
status (ls, st) - Show the status of the credential
end (quit, exit, x, q) - End, without saving any changes
commit (save) - Commit the changes to the credential
-- Password and MFA
password (passwd, pass, pw) - Set a new password
totp - Generate a new totp, requires a password to be set
totp remove (totp rm, trm) - Remove the TOTP of this account
backup codes (bcg, bcode) - (Re)generate backup codes for this account
remove (rm) - Remove only the password based credential
-- Passkeys
passkey (pk) - Add a new Passkey
passkey remove (passkey rm, pkrm) - Remove a Passkey
"#
        )
    }
}

impl FromStr for CUAction {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        match s.as_str() {
            "help" | "h" | "?" => Ok(CUAction::Help),
            "status" | "ls" | "st" => Ok(CUAction::Status),
            "end" | "quit" | "exit" | "x" | "q" => Ok(CUAction::End),
            "commit" | "save" => Ok(CUAction::Commit),
            "password" | "passwd" | "pass" | "pw" => Ok(CUAction::Password),
            "totp" => Ok(CUAction::Totp),
            "totp remove" | "totp rm" | "trm" => Ok(CUAction::TotpRemove),
            "backup codes" | "bcode" | "bcg" => Ok(CUAction::BackupCodes),
            "remove" | "rm" => Ok(CUAction::Remove),
            "passkey" | "pk" => Ok(CUAction::Passkey),
            "passkey remove" | "passkey rm" | "pkrm" => Ok(CUAction::PasskeyRemove),
            _ => Err(()),
        }
    }
}

async fn totp_enroll_prompt(session_token: &CUSessionToken, client: &KanidmClient) {
    // First, submit the server side gen.
    let totp_secret: TotpSecret = match client
        .idm_account_credential_update_init_totp(session_token)
        .await
    {
        Ok(CUStatus {
            mfaregstate: CURegState::TotpCheck(totp_secret),
            ..
        }) => totp_secret,
        Ok(status) => {
            debug!(?status);
            eprintln!("An error occured -> InvalidState");
            return;
        }
        Err(e) => {
            eprintln!("An error occured -> {:?}", e);
            return;
        }
    };

    // gen the qr
    println!("Scan the following QR code with your OTP app.");

    let code = match QrCode::new(totp_secret.to_uri().as_str()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to generate QR code -> {:?}", e);
            return;
        }
    };
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);

    println!("Alternatively, you can manually enter the following OTP details:");
    println!("--------------------------------------------------------------");
    println!("TOTP URI: {}", totp_secret.to_uri().as_str());
    println!("Account Name: {}", totp_secret.accountname);
    println!("Issuer: {}", totp_secret.issuer);
    println!("Algorithm: {}", totp_secret.algo);
    println!("Period/Step: {}", totp_secret.step);
    println!("Secret: {}", totp_secret.get_secret());

    // prompt for the totp.
    println!("--------------------------------------------------------------");
    println!("Enter a TOTP from your authenticator to complete registration:");

    // Up to three attempts
    let mut attempts = 3;
    while attempts > 0 {
        attempts -= 1;
        // prompt for it. OR cancel.
        let input: String = Input::new()
            .with_prompt("TOTP")
            .validate_with(|input: &String| -> Result<(), &str> {
                if input.to_lowercase().starts_with('c') || input.trim().parse::<u32>().is_ok() {
                    Ok(())
                } else {
                    Err("Must be a number (123456) or cancel to end")
                }
            })
            .interact_text()
            .unwrap();

        // cancel, submit the reg cancel.
        let totp_chal = match input.trim().parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Cancelling TOTP registration ...");
                if let Err(e) = client
                    .idm_account_credential_update_cancel_mfareg(session_token)
                    .await
                {
                    eprintln!("An error occured -> {:?}", e);
                } else {
                    println!("success");
                }
                return;
            }
        };
        trace!(%totp_chal);

        // Submit and see what we get.
        match client
            .idm_account_credential_update_check_totp(session_token, totp_chal)
            .await
        {
            Ok(CUStatus {
                mfaregstate: CURegState::None,
                ..
            }) => {
                println!("success");
                break;
            }
            Ok(CUStatus {
                mfaregstate: CURegState::TotpTryAgain,
                ..
            }) => {
                // Wrong code! Try again.
                eprintln!("Incorrect TOTP code entered. Please try again.");
                continue;
            }
            Ok(CUStatus {
                mfaregstate: CURegState::TotpInvalidSha1,
                ..
            }) => {
                // Sha 1 warning.
                eprintln!("⚠️  WARNING - It appears your authenticator app may be broken ⚠️  ");
                eprintln!(" The TOTP authenticator you are using is forcing the use of SHA1\n");
                eprintln!(
                    " SHA1 is a deprecated and potentially insecure cryptographic algorithm\n"
                );

                let items = vec!["Cancel", "I am sure"];
                let selection = Select::with_theme(&ColorfulTheme::default())
                    .items(&items)
                    .default(0)
                    .interact()
                    .unwrap();

                match selection {
                    1 => {
                        if let Err(e) = client
                            .idm_account_credential_update_accept_sha1_totp(session_token)
                            .await
                        {
                            eprintln!("An error occured -> {:?}", e);
                        } else {
                            println!("success");
                        }
                    }
                    _ => {
                        println!("Cancelling TOTP registration ...");
                        if let Err(e) = client
                            .idm_account_credential_update_cancel_mfareg(session_token)
                            .await
                        {
                            eprintln!("An error occured -> {:?}", e);
                        } else {
                            println!("success");
                        }
                    }
                }
                return;
            }
            Ok(status) => {
                debug!(?status);
                eprintln!("An error occured -> InvalidState");
                return;
            }
            Err(e) => {
                eprintln!("An error occured -> {:?}", e);
                return;
            }
        }
    }
    // Done!
}

async fn passkey_enroll_prompt(session_token: &CUSessionToken, client: &KanidmClient) {
    let pk_reg = match client
        .idm_account_credential_update_passkey_init(session_token)
        .await
    {
        Ok(CUStatus {
            mfaregstate: CURegState::Passkey(pk_reg),
            ..
        }) => pk_reg,
        Ok(status) => {
            debug!(?status);
            eprintln!("An error occured -> InvalidState");
            return;
        }
        Err(e) => {
            eprintln!("An error occured -> {:?}", e);
            return;
        }
    };

    // Setup and connect to the webauthn handler ...
    let mut wa = WebauthnAuthenticator::new(U2FHid::new());

    eprintln!("Your authenticator will now flash for you to interact with.");
    eprintln!("You may be asked to enter the PIN for your device.");

    let rego = match wa.do_registration(client.get_origin().clone(), pk_reg) {
        Ok(rego) => rego,
        Err(e) => {
            error!("Error Signing -> {:?}", e);
            return;
        }
    };

    let label: String = Input::new()
        .with_prompt("\nEnter a label for this Passkey # ")
        .allow_empty(false)
        .interact_text()
        .unwrap();

    match client
        .idm_account_credential_update_passkey_finish(session_token, label, rego)
        .await
    {
        Ok(_) => println!("success"),
        Err(e) => {
            eprintln!("An error occured -> {:?}", e);
        }
    };
}

// For webauthn later

/*
    AccountCredential::RegisterWebauthn(acsopt) => {
        let client = acsopt.copt.to_client().await;

        let (session, chal) = match client
            .idm_account_primary_credential_register_webauthn(
                acsopt.aopts.account_id.as_str(),
                acsopt.tag.as_str(),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                error!("Error Starting Registration -> {:?}", e);
                return;
            }
        };

        let mut wa = WebauthnAuthenticator::new(U2FHid::new());

        eprintln!("Your authenticator will now flash for you to interact with.");

        let rego = match wa.do_registration(client.get_origin(), chal) {
            Ok(rego) => rego,
            Err(e) => {
                error!("Error Signing -> {:?}", e);
                return;
            }
        };

        match client
            .idm_account_primary_credential_complete_webuthn_registration(
                acsopt.aopts.account_id.as_str(),
                rego,
                session,
            )
            .await
        {
            Ok(()) => {
                println!("Webauthn token registration success.");
            }
            Err(e) => {
                error!("Error Completing -> {:?}", e);
            }
        }
    }
*/

fn display_status(status: CUStatus) {
    let CUStatus {
        spn,
        displayname,
        can_commit,
        primary,
        mfaregstate: _,
        passkeys,
    } = status;

    println!("spn: {}", spn);
    println!("Name: {}", displayname);
    if let Some(cred_detail) = &primary {
        println!("Primary Credential:");
        print!("{}", cred_detail);
    } else {
        println!("Primary Credential:");
        println!("  not set");
    }
    println!("Passkeys:");
    if passkeys.is_empty() {
        println!("  not set");
    } else {
        for pk in passkeys {
            println!("  {} ({})", pk.tag, pk.uuid);
        }
    }

    // We may need to be able to display if there are dangling
    // curegstates, but the cli ui statemachine can match the
    // server so it may not be needed?

    println!("Can Commit: {}", can_commit);
}

/// This is the REPL for updating a credential for a given account
async fn credential_update_exec(
    session_token: CUSessionToken,
    status: CUStatus,
    client: KanidmClient,
) {
    trace!("started credential update exec");
    // Show the initial status,
    display_status(status);
    // Setup to work
    loop {
        // Display Prompt
        let input: String = Input::new()
            .with_prompt("\ncred update (? for help) # ")
            .validate_with(|input: &String| -> Result<(), &str> {
                if CUAction::from_str(input).is_ok() {
                    Ok(())
                } else {
                    Err("This is not a valid command. See help for valid options (?)")
                }
            })
            .interact_text()
            .unwrap();

        // Get action
        let action = match CUAction::from_str(&input) {
            Ok(a) => a,
            Err(_) => continue,
        };

        trace!(?action);

        match action {
            CUAction::Help => {
                print!("{}", action);
            }
            CUAction::Status => {
                match client
                    .idm_account_credential_update_status(&session_token)
                    .await
                {
                    Ok(status) => display_status(status),
                    Err(e) => {
                        eprintln!("An error occured -> {:?}", e);
                    }
                }
            }
            CUAction::Password => {
                let password_a = Password::new()
                    .with_prompt("New password")
                    .interact()
                    .unwrap();
                let password_b = Password::new()
                    .with_prompt("Confirm password")
                    .interact()
                    .unwrap();

                if password_a != password_b {
                    eprintln!("Passwords do not match");
                } else if let Err(e) = client
                    .idm_account_credential_update_set_password(&session_token, &password_a)
                    .await
                {
                    match e {
                        ClientErrorHttp(_, Some(PasswordQuality(feedback)), _) => {
                            for fb_item in feedback.iter() {
                                eprintln!("{:?}", fb_item)
                            }
                        }
                        _ => eprintln!("An error occured -> {:?}", e),
                    }
                } else {
                    println!("Successfully reset password.");
                }
            }
            CUAction::Totp => totp_enroll_prompt(&session_token, &client).await,
            CUAction::TotpRemove => {
                if Confirm::new()
                    .with_prompt("Do you want to remove your totp?")
                    .interact()
                    .unwrap()
                {
                    if let Err(e) = client
                        .idm_account_credential_update_remove_totp(&session_token)
                        .await
                    {
                        eprintln!("An error occured -> {:?}", e);
                    } else {
                        println!("success");
                    }
                } else {
                    println!("Totp was NOT removed");
                }
            }
            CUAction::BackupCodes => {
                match client
                    .idm_account_credential_update_backup_codes_generate(&session_token)
                    .await
                {
                    Ok(CUStatus {
                        mfaregstate: CURegState::BackupCodes(codes),
                        ..
                    }) => {
                        println!("Please store these Backup codes in a safe place");
                        println!("They will only be displayed ONCE");
                        for code in codes {
                            println!("  {}", code)
                        }
                    }
                    Ok(status) => {
                        debug!(?status);
                        eprintln!("An error occured -> InvalidState");
                    }
                    Err(e) => {
                        eprintln!("An error occured -> {:?}", e);
                    }
                }
            }
            CUAction::Remove => {
                if Confirm::new()
                    .with_prompt("Do you want to remove your primary credential?")
                    .interact()
                    .unwrap()
                {
                    if let Err(e) = client
                        .idm_account_credential_update_primary_remove(&session_token)
                        .await
                    {
                        eprintln!("An error occured -> {:?}", e);
                    } else {
                        println!("success");
                    }
                } else {
                    println!("Primary credential was NOT removed");
                }
            }
            CUAction::Passkey => passkey_enroll_prompt(&session_token, &client).await,
            CUAction::PasskeyRemove => {
                // TODO: make this a scrollable selector with a "cancel" option as the default
                match client
                .idm_account_credential_update_status(&session_token)
                .await
                    {
                        Ok(status) => {
                            if status.passkeys.is_empty() {
                                println!("No passkeys are configured for this user");
                                return
                            }
                            println!("Current passkeys:");
                            for pk in status.passkeys {
                                println!("  {} ({})", pk.tag, pk.uuid);
                            }
                        },
                        Err(e) => {
                            eprintln!("An error occured pulling existing credentials -> {:?}", e);
                        }
                    }
                let uuid_s: String = Input::new()
                    .with_prompt("\nEnter the UUID of the Passkey to remove (blank to stop) # ")
                    .validate_with(|input: &String| -> Result<(), &str> {
                        if input.is_empty() || Uuid::parse_str(input).is_ok() {
                            Ok(())
                        } else {
                            Err("This is not a valid UUID")
                        }
                    })
                    .allow_empty(true)
                    .interact_text()
                    .unwrap();

                // Remeber, if it's NOT a valid uuid, it must have been empty as a termination.
                if let Ok(uuid) = Uuid::parse_str(&uuid_s) {
                    if let Err(e) = client
                        .idm_account_credential_update_passkey_remove(&session_token, uuid)
                        .await
                    {
                        eprintln!("An error occured -> {:?}", e);
                    } else {
                        println!("success");
                    }
                } else {
                    println!("Passkeys were NOT changed");
                }
            }
            CUAction::End => {
                println!("Changes were NOT saved.");
                break;
            }
            CUAction::Commit => {
                if Confirm::new()
                    .with_prompt("Do you want to commit your changes?")
                    .interact()
                    .unwrap()
                {
                    if let Err(e) = client
                        .idm_account_credential_update_commit(&session_token)
                        .await
                    {
                        eprintln!("An error occured -> {:?}", e);
                    } else {
                        println!("success");
                    }
                    break;
                } else {
                    println!("Changes have NOT been saved.");
                }
            }
        }
    }
    trace!("ended credential update exec");
}
