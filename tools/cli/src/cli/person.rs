use crate::common::{try_expire_at_from_string, OpType};
use std::fmt::{self, Debug};
use std::str::FromStr;

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password, Select};
use kanidm_client::ClientError::Http as ClientErrorHttp;
use kanidm_client::KanidmClient;
use kanidm_proto::constants::{
    ATTR_ACCOUNT_EXPIRE, ATTR_ACCOUNT_VALID_FROM, ATTR_GIDNUMBER, ATTR_SSH_PUBLICKEY,
};
use kanidm_proto::internal::OperationError::PasswordQuality;
use kanidm_proto::internal::{
    CUCredState, CUExtPortal, CUIntentToken, CURegState, CURegWarning, CUSessionToken, CUStatus,
    TotpSecret,
};
use kanidm_proto::internal::{CredentialDetail, CredentialDetailType};
use kanidm_proto::messages::{AccountChangeMessage, ConsoleOutputMode, MessageStatus};
use qrcode::render::unicode;
use qrcode::QrCode;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::webauthn::get_authenticator;
use crate::{
    handle_client_error, password_prompt, AccountCertificate, AccountCredential, AccountRadius,
    AccountSsh, AccountUserAuthToken, AccountValidity, OutputMode, PersonOpt, PersonPosix,
};

impl PersonOpt {
    pub fn debug(&self) -> bool {
        match self {
            PersonOpt::Credential { commands } => commands.debug(),
            PersonOpt::Radius { commands } => match commands {
                AccountRadius::Show(aro) => aro.copt.debug,
                AccountRadius::Generate(aro) => aro.copt.debug,
                AccountRadius::DeleteSecret(aro) => aro.copt.debug,
            },
            PersonOpt::Posix { commands } => match commands {
                PersonPosix::Show(apo) => apo.copt.debug,
                PersonPosix::Set(apo) => apo.copt.debug,
                PersonPosix::SetPassword(apo) => apo.copt.debug,
                PersonPosix::ResetGidnumber { copt, .. } => copt.debug,
            },
            PersonOpt::Session { commands } => match commands {
                AccountUserAuthToken::Status(apo) => apo.copt.debug,
                AccountUserAuthToken::Destroy { copt, .. } => copt.debug,
            },
            PersonOpt::Ssh { commands } => match commands {
                AccountSsh::List(ano) => ano.copt.debug,
                AccountSsh::Add(ano) => ano.copt.debug,
                AccountSsh::Delete(ano) => ano.copt.debug,
            },
            PersonOpt::List(copt) => copt.debug,
            PersonOpt::Get(aopt) => aopt.copt.debug,
            PersonOpt::Update(aopt) => aopt.copt.debug,
            PersonOpt::Delete(aopt) => aopt.copt.debug,
            PersonOpt::Create(aopt) => aopt.copt.debug,
            PersonOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => ano.copt.debug,
                AccountValidity::ExpireAt(ano) => ano.copt.debug,
                AccountValidity::BeginFrom(ano) => ano.copt.debug,
            },
            PersonOpt::Certificate { commands } => match commands {
                AccountCertificate::Status { copt, .. }
                | AccountCertificate::Create { copt, .. } => copt.debug,
            },
            PersonOpt::Search { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            // id/cred/primary/set
            PersonOpt::Credential { commands } => commands.exec().await,
            PersonOpt::Radius { commands } => match commands {
                AccountRadius::Show(aopt) => {
                    let client = aopt.copt.to_client(OpType::Read).await;

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
                        Err(e) => handle_client_error(e, aopt.copt.output_mode),
                    }
                }
                AccountRadius::Generate(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_account_radius_credential_regenerate(aopt.aopts.account_id.as_str())
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
                AccountRadius::DeleteSecret(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
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
            }, // end PersonOpt::Radius
            PersonOpt::Posix { commands } => match commands {
                PersonPosix::Show(aopt) => {
                    let client = aopt.copt.to_client(OpType::Read).await;
                    match client
                        .idm_account_unix_token_get(aopt.aopts.account_id.as_str())
                        .await
                    {
                        Ok(token) => println!("{}", token),
                        Err(e) => handle_client_error(e, aopt.copt.output_mode),
                    }
                }
                PersonPosix::Set(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_person_account_unix_extend(
                            aopt.aopts.account_id.as_str(),
                            aopt.gidnumber,
                            aopt.shell.as_deref(),
                        )
                        .await
                    {
                        handle_client_error(e, aopt.copt.output_mode)
                    }
                }
                PersonPosix::SetPassword(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    let password = match password_prompt("Enter new posix (sudo) password: ") {
                        Some(v) => v,
                        None => {
                            println!("Passwords do not match");
                            return;
                        }
                    };

                    if let Err(e) = client
                        .idm_person_account_unix_cred_put(
                            aopt.aopts.account_id.as_str(),
                            password.as_str(),
                        )
                        .await
                    {
                        handle_client_error(e, aopt.copt.output_mode)
                    }
                }
                PersonPosix::ResetGidnumber { copt, account_id } => {
                    let client = copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_person_account_purge_attr(account_id.as_str(), ATTR_GIDNUMBER)
                        .await
                    {
                        handle_client_error(e, copt.output_mode)
                    }
                }
            }, // end PersonOpt::Posix
            PersonOpt::Session { commands } => match commands {
                AccountUserAuthToken::Status(apo) => {
                    let client = apo.copt.to_client(OpType::Read).await;
                    match client
                        .idm_account_list_user_auth_token(apo.aopts.account_id.as_str())
                        .await
                    {
                        Ok(tokens) => {
                            if tokens.is_empty() {
                                println!("No sessions exist");
                            } else {
                                for token in tokens {
                                    println!("token: {}", token);
                                }
                            }
                        }
                        Err(e) => handle_client_error(e, apo.copt.output_mode),
                    }
                }
                AccountUserAuthToken::Destroy {
                    aopts,
                    copt,
                    session_id,
                } => {
                    let client = copt.to_client(OpType::Write).await;
                    match client
                        .idm_account_destroy_user_auth_token(aopts.account_id.as_str(), *session_id)
                        .await
                    {
                        Ok(()) => {
                            println!("Success");
                        }
                        Err(e) => {
                            error!("Error destroying account session");
                            handle_client_error(e, copt.output_mode);
                        }
                    }
                }
            }, // End PersonOpt::Session
            PersonOpt::Ssh { commands } => match commands {
                AccountSsh::List(aopt) => {
                    let client = aopt.copt.to_client(OpType::Read).await;

                    match client
                        .idm_person_account_get_attr(
                            aopt.aopts.account_id.as_str(),
                            ATTR_SSH_PUBLICKEY,
                        )
                        .await
                    {
                        Ok(pkeys) => pkeys.iter().flatten().for_each(|pkey| println!("{}", pkey)),
                        Err(e) => handle_client_error(e, aopt.copt.output_mode),
                    }
                }
                AccountSsh::Add(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_person_account_post_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                            aopt.pubkey.as_str(),
                        )
                        .await
                    {
                        handle_client_error(e, aopt.copt.output_mode)
                    }
                }
                AccountSsh::Delete(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_person_account_delete_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                        )
                        .await
                    {
                        handle_client_error(e, aopt.copt.output_mode)
                    }
                }
            }, // end PersonOpt::Ssh
            PersonOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_person_account_list().await {
                    Ok(r) => match copt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{}", ent)),
                    },
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            PersonOpt::Search { copt, account_id } => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_person_search(account_id).await {
                    Ok(r) => match copt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{}", ent)),
                    },
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            PersonOpt::Update(aopt) => {
                let client = aopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_person_account_update(
                        aopt.aopts.account_id.as_str(),
                        aopt.newname.as_deref(),
                        aopt.displayname.as_deref(),
                        aopt.legalname.as_deref(),
                        aopt.mail.as_deref(),
                    )
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, aopt.copt.output_mode),
                }
            }
            PersonOpt::Get(aopt) => {
                let client = aopt.copt.to_client(OpType::Read).await;
                match client
                    .idm_person_account_get(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok(Some(e)) => match aopt.copt.output_mode {
                        OutputMode::Json => {
                            println!(
                                "{}",
                                serde_json::to_string(&e).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => println!("{}", e),
                    },
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, aopt.copt.output_mode),
                }
            }
            PersonOpt::Delete(aopt) => {
                let client = aopt.copt.to_client(OpType::Write).await;
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
                    .idm_person_account_delete(aopt.aopts.account_id.as_str())
                    .await
                {
                    Err(e) => {
                        modmessage.result = format!("Error -> {:?}", e);
                        modmessage.status = MessageStatus::Failure;
                        eprintln!("{}", modmessage);

                        // handle_client_error(e, aopt.copt.output_mode),
                    }
                    Ok(result) => {
                        debug!("{:?}", result);
                        println!("{}", modmessage);
                    }
                };
            }
            PersonOpt::Create(acopt) => {
                let client = acopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_person_account_create(
                        acopt.aopts.account_id.as_str(),
                        acopt.display_name.as_str(),
                    )
                    .await
                {
                    Ok(_) => {
                        println!(
                            "Successfully created display_name=\"{}\" username={}",
                            acopt.display_name.as_str(),
                            acopt.aopts.account_id.as_str(),
                        )
                    }
                    Err(e) => handle_client_error(e, acopt.copt.output_mode),
                }
            }
            PersonOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => {
                    let client = ano.copt.to_client(OpType::Read).await;

                    let entry = match client
                        .idm_person_account_get(ano.aopts.account_id.as_str())
                        .await
                    {
                        Err(err) => {
                            error!(
                                "No account {} found, or other error occurred: {:?}",
                                ano.aopts.account_id.as_str(),
                                err
                            );
                            return;
                        }
                        Ok(val) => match val {
                            Some(val) => val,
                            None => {
                                error!("No account {} found!", ano.aopts.account_id.as_str());
                                return;
                            }
                        },
                    };

                    println!("user: {}", ano.aopts.account_id.as_str());
                    if let Some(t) = entry.attrs.get(ATTR_ACCOUNT_VALID_FROM) {
                        // Convert the time to local timezone.
                        let t = OffsetDateTime::parse(&t[0], &Rfc3339)
                            .map(|odt| {
                                odt.to_offset(
                                    time::UtcOffset::local_offset_at(OffsetDateTime::UNIX_EPOCH)
                                        .unwrap_or(time::UtcOffset::UTC),
                                )
                                .format(&Rfc3339)
                                .unwrap_or(odt.to_string())
                            })
                            .unwrap_or_else(|_| "invalid timestamp".to_string());

                        println!("valid after: {}", t);
                    } else {
                        println!("valid after: any time");
                    }

                    if let Some(t) = entry.attrs.get(ATTR_ACCOUNT_EXPIRE) {
                        let t = OffsetDateTime::parse(&t[0], &Rfc3339)
                            .map(|odt| {
                                odt.to_offset(
                                    time::UtcOffset::local_offset_at(OffsetDateTime::UNIX_EPOCH)
                                        .unwrap_or(time::UtcOffset::UTC),
                                )
                                .format(&Rfc3339)
                                .unwrap_or(odt.to_string())
                            })
                            .unwrap_or_else(|_| "invalid timestamp".to_string());
                        println!("expire: {}", t);
                    } else {
                        println!("expire: never");
                    }
                }
                AccountValidity::ExpireAt(ano) => {
                    let client = ano.copt.to_client(OpType::Write).await;
                    let validity = match try_expire_at_from_string(ano.datetime.as_str()) {
                        Ok(val) => val,
                        Err(()) => return,
                    };
                    let res = match validity {
                        None => {
                            client
                                .idm_person_account_purge_attr(
                                    ano.aopts.account_id.as_str(),
                                    ATTR_ACCOUNT_EXPIRE,
                                )
                                .await
                        }
                        Some(new_expiry) => {
                            client
                                .idm_person_account_set_attr(
                                    ano.aopts.account_id.as_str(),
                                    ATTR_ACCOUNT_EXPIRE,
                                    &[&new_expiry],
                                )
                                .await
                        }
                    };
                    match res {
                        Err(e) => handle_client_error(e, ano.copt.output_mode),
                        _ => println!("Success"),
                    };
                }
                AccountValidity::BeginFrom(ano) => {
                    let client = ano.copt.to_client(OpType::Write).await;
                    if matches!(ano.datetime.as_str(), "any" | "clear" | "whenever") {
                        // Unset the value
                        match client
                            .idm_person_account_purge_attr(
                                ano.aopts.account_id.as_str(),
                                ATTR_ACCOUNT_VALID_FROM,
                            )
                            .await
                        {
                            Err(e) => error!(
                                "Error setting begin-from to '{}' -> {:?}",
                                ano.datetime.as_str(),
                                e
                            ),
                            _ => println!("Success"),
                        }
                    } else {
                        // Attempt to parse and set
                        if let Err(e) = OffsetDateTime::parse(ano.datetime.as_str(), &Rfc3339) {
                            error!("Error -> {:?}", e);
                            return;
                        }

                        match client
                            .idm_person_account_set_attr(
                                ano.aopts.account_id.as_str(),
                                ATTR_ACCOUNT_VALID_FROM,
                                &[ano.datetime.as_str()],
                            )
                            .await
                        {
                            Err(e) => error!(
                                "Error setting begin-from to '{}' -> {:?}",
                                ano.datetime.as_str(),
                                e
                            ),
                            _ => println!("Success"),
                        }
                    }
                }
            }, // end PersonOpt::Validity
            PersonOpt::Certificate { commands } => commands.exec().await,
        }
    }
}

impl AccountCertificate {
    pub async fn exec(&self) {
        match self {
            AccountCertificate::Status { account_id, copt } => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_person_certificate_list(account_id).await {
                    Ok(r) => match copt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => {
                            if r.is_empty() {
                                println!("No certificates available")
                            } else {
                                r.iter().for_each(|ent| println!("{}", ent))
                            }
                        }
                    },
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            AccountCertificate::Create {
                account_id,
                certificate_path,
                copt,
            } => {
                let pem_data = match tokio::fs::read_to_string(certificate_path).await {
                    Ok(pd) => pd,
                    Err(io_err) => {
                        error!(?io_err, ?certificate_path, "Unable to read PEM data");
                        return;
                    }
                };

                let client = copt.to_client(OpType::Write).await;

                if let Err(e) = client
                    .idm_person_certificate_create(account_id, &pem_data)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Success");
                };
            }
        }
    }
}

impl AccountCredential {
    pub fn debug(&self) -> bool {
        match self {
            AccountCredential::Status(aopt) => aopt.copt.debug,
            AccountCredential::CreateResetToken { copt, .. } => copt.debug,
            AccountCredential::UseResetToken(aopt) => aopt.copt.debug,
            AccountCredential::Update(aopt) => aopt.copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            AccountCredential::Status(aopt) => {
                let client = aopt.copt.to_client(OpType::Read).await;
                match client
                    .idm_person_account_get_credential_status(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok(cstatus) => {
                        println!("{}", cstatus);
                    }
                    Err(e) => {
                        error!("Error getting credential status -> {:?}", e);
                    }
                }
            }
            AccountCredential::Update(aopt) => {
                let client = aopt.copt.to_client(OpType::Write).await;
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
                                    status_code, error
                                );
                            }
                            _ => error!("Error starting use_reset_token -> {:?}", e),
                        };
                    }
                }
            }
            AccountCredential::CreateResetToken { aopts, copt, ttl } => {
                let client = copt.to_client(OpType::Write).await;

                // What's the client url?
                match client
                    .idm_person_account_credential_update_intent(aopts.account_id.as_str(), *ttl)
                    .await
                {
                    Ok(cuintent_token) => {
                        let mut url = client.make_url("/ui/reset");
                        url.query_pairs_mut()
                            .append_pair("token", cuintent_token.token.as_str());

                        debug!(
                            "Successfully created credential reset token for {}: {}",
                            aopts.account_id, cuintent_token.token
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
                            "Or run this command: kanidm person credential use-reset-token {}",
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
    AttestedPasskey,
    AttestedPasskeyRemove,
    UnixPassword,
    UnixPasswordRemove,
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
-- Attested Passkeys
attested-passkey (apk) - Add a new Attested Passkey
attested-passkey-remove (attested-passkey rm, apkrm) - Remove an Attested Passkey
-- Unix (sudo) Password
unix-password (upasswd, upass, upw) - Set a new unix/sudo password
unix-password-remove (upassrm upwrm) - Remove the accounts unix password
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
            "attested-passkey" | "apk" => Ok(CUAction::AttestedPasskey),
            "attested-passkey remove" | "attested-passkey rm" | "apkrm" => {
                Ok(CUAction::AttestedPasskeyRemove)
            }
            "unix-password" | "upasswd" | "upass" | "upw" => Ok(CUAction::UnixPassword),
            "unix-password-remove" | "upassrm" | "upwrm" => Ok(CUAction::UnixPasswordRemove),
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
            eprintln!("An error occurred -> InvalidState");
            return;
        }
        Err(e) => {
            eprintln!("An error occurred -> {:?}", e);
            return;
        }
    };

    let label: String = Input::new()
        .with_prompt("TOTP Label")
        .interact_text()
        .expect("Failed to interact with interactive session");

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
            .expect("Failed to interact with interactive session");

        // cancel, submit the reg cancel.
        let totp_chal = match input.trim().parse::<u32>() {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Cancelling TOTP registration ...");
                if let Err(e) = client
                    .idm_account_credential_update_cancel_mfareg(session_token)
                    .await
                {
                    eprintln!("An error occurred -> {:?}", e);
                } else {
                    println!("success");
                }
                return;
            }
        };
        trace!(%totp_chal);

        // Submit and see what we get.
        match client
            .idm_account_credential_update_check_totp(session_token, totp_chal, &label)
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
                    .expect("Failed to interact with interactive session");

                match selection {
                    1 => {
                        if let Err(e) = client
                            .idm_account_credential_update_accept_sha1_totp(session_token)
                            .await
                        {
                            eprintln!("An error occurred -> {:?}", e);
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
                            eprintln!("An error occurred -> {:?}", e);
                        } else {
                            println!("success");
                        }
                    }
                }
                return;
            }
            Ok(status) => {
                debug!(?status);
                eprintln!("An error occurred -> InvalidState");
                return;
            }
            Err(e) => {
                eprintln!("An error occurred -> {:?}", e);
                return;
            }
        }
    }
    // Done!
}

#[derive(Clone, Copy)]
enum PasskeyClass {
    Any,
    Attested,
}

impl fmt::Display for PasskeyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasskeyClass::Any => write!(f, "Passkey"),
            PasskeyClass::Attested => write!(f, "Attested Passkey"),
        }
    }
}

async fn passkey_enroll_prompt(
    session_token: &CUSessionToken,
    client: &KanidmClient,
    pk_class: PasskeyClass,
) {
    let pk_reg = match pk_class {
        PasskeyClass::Any => {
            match client
                .idm_account_credential_update_passkey_init(session_token)
                .await
            {
                Ok(CUStatus {
                    mfaregstate: CURegState::Passkey(pk_reg),
                    ..
                }) => pk_reg,
                Ok(status) => {
                    debug!(?status);
                    eprintln!("An error occurred -> InvalidState");
                    return;
                }
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                    return;
                }
            }
        }
        PasskeyClass::Attested => {
            match client
                .idm_account_credential_update_attested_passkey_init(session_token)
                .await
            {
                Ok(CUStatus {
                    mfaregstate: CURegState::AttestedPasskey(pk_reg),
                    ..
                }) => pk_reg,
                Ok(status) => {
                    debug!(?status);
                    eprintln!("An error occurred -> InvalidState");
                    return;
                }
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                    return;
                }
            }
        }
    };

    // Setup and connect to the webauthn handler ...
    let mut wa = get_authenticator();

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
        .expect("Failed to interact with interactive session");

    match pk_class {
        PasskeyClass::Any => {
            match client
                .idm_account_credential_update_passkey_finish(session_token, label, rego)
                .await
            {
                Ok(_) => println!("success"),
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                }
            }
        }
        PasskeyClass::Attested => {
            match client
                .idm_account_credential_update_attested_passkey_finish(session_token, label, rego)
                .await
            {
                Ok(_) => println!("success"),
                Err(e) => {
                    eprintln!("An error occurred -> {:?}", e);
                }
            }
        }
    }
}

async fn passkey_remove_prompt(
    session_token: &CUSessionToken,
    client: &KanidmClient,
    pk_class: PasskeyClass,
) {
    // TODO: make this a scrollable selector with a "cancel" option as the default
    match client
        .idm_account_credential_update_status(session_token)
        .await
    {
        Ok(status) => match pk_class {
            PasskeyClass::Any => {
                if status.passkeys.is_empty() {
                    println!("No passkeys are configured for this user");
                    return;
                }
                println!("Current passkeys:");
                for pk in status.passkeys {
                    println!("  {} ({})", pk.tag, pk.uuid);
                }
            }
            PasskeyClass::Attested => {
                if status.attested_passkeys.is_empty() {
                    println!("No attested passkeys are configured for this user");
                    return;
                }
                println!("Current attested passkeys:");
                for pk in status.attested_passkeys {
                    println!("  {} ({})", pk.tag, pk.uuid);
                }
            }
        },
        Err(e) => {
            eprintln!(
                "An error occurred retrieving existing credentials -> {:?}",
                e
            );
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
        .expect("Failed to interact with interactive session");

    // Remember, if it's NOT a valid uuid, it must have been empty as a termination.
    if let Ok(uuid) = Uuid::parse_str(&uuid_s) {
        let result = match pk_class {
            PasskeyClass::Any => {
                client
                    .idm_account_credential_update_passkey_remove(session_token, uuid)
                    .await
            }
            PasskeyClass::Attested => {
                client
                    .idm_account_credential_update_attested_passkey_remove(session_token, uuid)
                    .await
            }
        };

        if let Err(e) = result {
            eprintln!("An error occurred -> {:?}", e);
        } else {
            println!("success");
        }
    } else {
        println!("{}s were NOT changed", pk_class);
    }
}

fn display_warnings(warnings: &[CURegWarning]) {
    if !warnings.is_empty() {
        println!("Warnings:");
    }
    for warning in warnings {
        print!(" ⚠️   ");
        match warning {
            CURegWarning::MfaRequired => {
                println!("Multi-factor authentication required - add TOTP or replace your password with more secure method.");
            }
            CURegWarning::PasskeyRequired => {
                println!("Passkeys required");
            }
            CURegWarning::AttestedPasskeyRequired => {
                println!("Attested Passkeys required");
            }
            CURegWarning::AttestedResidentKeyRequired => {
                println!("Attested Resident Keys required");
            }
            CURegWarning::WebauthnAttestationUnsatisfiable => {
                println!("Attestation is unsatisfiable. Contact your administrator.");
            }
            CURegWarning::Unsatisfiable => {
                println!("Account policy is unsatisfiable. Contact your administrator.");
            }
        }
    }
}

fn display_status(status: CUStatus) {
    let CUStatus {
        spn,
        displayname,
        ext_cred_portal,
        mfaregstate: _,
        can_commit,
        warnings,
        primary,
        primary_state,
        passkeys,
        passkeys_state,
        attested_passkeys,
        attested_passkeys_state,
        attested_passkeys_allowed_devices,
        unixcred,
        unixcred_state,
        sshkeys,
        sshkeys_state,
    } = status;

    println!("spn: {}", spn);
    println!("Name: {}", displayname);

    match ext_cred_portal {
        CUExtPortal::None => {}
        CUExtPortal::Hidden => {
            println!("Externally Managed: Not all features may be available");
            println!("    Contact your admin for more details.");
        }
        CUExtPortal::Some(url) => {
            println!("Externally Managed: Not all features may be available");
            println!("    Visit {} to update your account details.", url.as_str());
        }
    };

    println!("Primary Credential:");

    match primary_state {
        CUCredState::Modifiable => {
            if let Some(cred_detail) = &primary {
                print!("{}", cred_detail);
            } else {
                println!("  not set");
            }
        }
        CUCredState::DeleteOnly => {
            if let Some(cred_detail) = &primary {
                print!("{}", cred_detail);
            } else {
                println!("  unable to modify - access denied");
            }
        }
        CUCredState::AccessDeny => {
            println!("  unable to modify - access denied");
        }
        CUCredState::PolicyDeny => {
            println!("  unable to modify - account policy denied");
        }
    }

    println!("Passkeys:");
    match passkeys_state {
        CUCredState::Modifiable => {
            if passkeys.is_empty() {
                println!("  not set");
            } else {
                for pk in passkeys {
                    println!("  {} ({})", pk.tag, pk.uuid);
                }
            }
        }
        CUCredState::DeleteOnly => {
            if passkeys.is_empty() {
                println!("  unable to modify - access denied");
            } else {
                for pk in passkeys {
                    println!("  {} ({})", pk.tag, pk.uuid);
                }
            }
        }
        CUCredState::AccessDeny => {
            println!("  unable to modify - access denied");
        }
        CUCredState::PolicyDeny => {
            println!("  unable to modify - account policy denied");
        }
    }

    println!("Attested Passkeys:");
    match attested_passkeys_state {
        CUCredState::Modifiable => {
            if attested_passkeys.is_empty() {
                println!("  not set");
            } else {
                for pk in attested_passkeys {
                    println!("  {} ({})", pk.tag, pk.uuid);
                }
            }

            println!("  --");
            println!("  The following devices models are allowed by account policy");
            for dev in attested_passkeys_allowed_devices {
                println!("  - {}", dev);
            }
        }
        CUCredState::DeleteOnly => {
            if attested_passkeys.is_empty() {
                println!("  unable to modify - attestation policy not configured");
            } else {
                for pk in attested_passkeys {
                    println!("  {} ({})", pk.tag, pk.uuid);
                }
            }
        }
        CUCredState::AccessDeny => {
            println!("  unable to modify - access denied");
        }
        CUCredState::PolicyDeny => {
            println!("  unable to modify - attestation policy not configured");
        }
    }

    println!("Unix (sudo) Password:");
    match unixcred_state {
        CUCredState::Modifiable => {
            if let Some(cred_detail) = &unixcred {
                print!("{}", cred_detail);
            } else {
                println!("  not set");
            }
        }
        CUCredState::DeleteOnly => {
            if let Some(cred_detail) = &unixcred {
                print!("{}", cred_detail);
            } else {
                println!("  unable to modify - access denied");
            }
        }
        CUCredState::AccessDeny => {
            println!("  unable to modify - access denied");
        }
        CUCredState::PolicyDeny => {
            println!("  unable to modify - account does not have posix attributes");
        }
    }

    println!("SSH Public Keys:");
    match sshkeys_state {
        CUCredState::Modifiable => {
            if sshkeys.is_empty() {
                println!("  not set");
            } else {
                for (label, sk) in sshkeys {
                    println!("  {}: {}", label, sk);
                }
            }
        }
        CUCredState::DeleteOnly => {
            if sshkeys.is_empty() {
                println!("  unable to modify - access denied");
            } else {
                for (label, sk) in sshkeys {
                    println!("  {}: {}", label, sk);
                }
            }
        }
        CUCredState::AccessDeny => {
            println!("  unable to modify - access denied");
        }
        CUCredState::PolicyDeny => {
            println!("  unable to modify - account policy denied");
        }
    }

    // We may need to be able to display if there are dangling
    // curegstates, but the cli ui statemachine can match the
    // server so it may not be needed?
    display_warnings(&warnings);

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
            .expect("Failed to interact with interactive session");

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
                        eprintln!("An error occurred -> {:?}", e);
                    }
                }
            }
            CUAction::Password => {
                let password_a = Password::new()
                    .with_prompt("New password")
                    .interact()
                    .expect("Failed to interact with interactive session");
                let password_b = Password::new()
                    .with_prompt("Confirm password")
                    .interact()
                    .expect("Failed to interact with interactive session");

                if password_a != password_b {
                    eprintln!("Passwords do not match");
                } else if let Err(e) = client
                    .idm_account_credential_update_set_password(&session_token, &password_a)
                    .await
                {
                    match e {
                        ClientErrorHttp(_, Some(PasswordQuality(feedback)), _) => {
                            eprintln!("Password was not secure enough, please consider the following suggestions:");
                            for fb_item in feedback.iter() {
                                eprintln!(" - {}", fb_item)
                            }
                        }
                        _ => eprintln!("An error occurred -> {:?}", e),
                    }
                } else {
                    println!("Successfully reset password.");
                }
            }
            CUAction::Totp => totp_enroll_prompt(&session_token, &client).await,
            CUAction::TotpRemove => {
                match client
                    .idm_account_credential_update_status(&session_token)
                    .await
                {
                    Ok(status) => match status.primary {
                        Some(CredentialDetail {
                            uuid: _,
                            type_: CredentialDetailType::PasswordMfa(totp_labels, ..),
                        }) => {
                            if totp_labels.is_empty() {
                                println!("No totps are configured for this user");
                                return;
                            } else {
                                println!("Current totps:");
                                for totp_label in totp_labels {
                                    println!("  {}", totp_label);
                                }
                            }
                        }
                        _ => {
                            println!("No totps are configured for this user");
                            return;
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "An error occurred retrieving existing credentials -> {:?}",
                            e
                        );
                    }
                }

                let label: String = Input::new()
                    .with_prompt("\nEnter the label of the Passkey to remove (blank to stop) # ")
                    .allow_empty(true)
                    .interact_text()
                    .expect("Failed to interact with interactive session");

                if !label.is_empty() {
                    if let Err(e) = client
                        .idm_account_credential_update_remove_totp(&session_token, &label)
                        .await
                    {
                        eprintln!("An error occurred -> {:?}", e);
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
                        eprintln!("An error occurred -> InvalidState");
                    }
                    Err(e) => {
                        eprintln!("An error occurred -> {:?}", e);
                    }
                }
            }
            CUAction::Remove => {
                if Confirm::new()
                    .with_prompt("Do you want to remove your primary credential?")
                    .interact()
                    .expect("Failed to interact with interactive session")
                {
                    if let Err(e) = client
                        .idm_account_credential_update_primary_remove(&session_token)
                        .await
                    {
                        eprintln!("An error occurred -> {:?}", e);
                    } else {
                        println!("success");
                    }
                } else {
                    println!("Primary credential was NOT removed");
                }
            }
            CUAction::Passkey => {
                passkey_enroll_prompt(&session_token, &client, PasskeyClass::Any).await
            }
            CUAction::PasskeyRemove => {
                passkey_remove_prompt(&session_token, &client, PasskeyClass::Any).await
            }
            CUAction::AttestedPasskey => {
                passkey_enroll_prompt(&session_token, &client, PasskeyClass::Attested).await
            }
            CUAction::AttestedPasskeyRemove => {
                passkey_remove_prompt(&session_token, &client, PasskeyClass::Attested).await
            }

            CUAction::UnixPassword => {
                let password_a = Password::new()
                    .with_prompt("New Unix Password")
                    .interact()
                    .expect("Failed to interact with interactive session");
                let password_b = Password::new()
                    .with_prompt("Confirm password")
                    .interact()
                    .expect("Failed to interact with interactive session");

                if password_a != password_b {
                    eprintln!("Passwords do not match");
                } else if let Err(e) = client
                    .idm_account_credential_update_set_unix_password(&session_token, &password_a)
                    .await
                {
                    match e {
                        ClientErrorHttp(_, Some(PasswordQuality(feedback)), _) => {
                            eprintln!("Password was not secure enough, please consider the following suggestions:");
                            for fb_item in feedback.iter() {
                                eprintln!(" - {}", fb_item)
                            }
                        }
                        _ => eprintln!("An error occurred -> {:?}", e),
                    }
                } else {
                    println!("Successfully reset unix password.");
                }
            }

            CUAction::UnixPasswordRemove => {
                if Confirm::new()
                    .with_prompt("Do you want to remove your unix password?")
                    .interact()
                    .expect("Failed to interact with interactive session")
                {
                    if let Err(e) = client
                        .idm_account_credential_update_unix_remove(&session_token)
                        .await
                    {
                        eprintln!("An error occurred -> {:?}", e);
                    } else {
                        println!("success");
                    }
                } else {
                    println!("unix password was NOT removed");
                }
            }

            CUAction::End => {
                println!("Changes were NOT saved.");
                break;
            }
            CUAction::Commit => {
                match client
                    .idm_account_credential_update_status(&session_token)
                    .await
                {
                    Ok(status) => {
                        if !status.can_commit {
                            display_warnings(&status.warnings);
                            // Reset the loop
                            println!("Changes have NOT been saved.");
                            continue;
                        }
                        // Can proceed
                    }
                    Err(e) => {
                        eprintln!("An error occurred -> {:?}", e);
                    }
                }

                if Confirm::new()
                    .with_prompt("Do you want to commit your changes?")
                    .interact()
                    .expect("Failed to interact with interactive session")
                {
                    if let Err(e) = client
                        .idm_account_credential_update_commit(&session_token)
                        .await
                    {
                        eprintln!("An error occurred -> {:?}", e);
                        println!("Changes have NOT been saved.");
                    } else {
                        println!("Success - Changes have been saved.");
                        break;
                    }
                } else {
                    println!("Changes have NOT been saved.");
                }
            }
        }
    }
    trace!("ended credential update exec");
}
