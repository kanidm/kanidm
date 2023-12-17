use crate::common::{try_expire_at_from_string, OpType};
use kanidm_proto::constants::{ATTR_ACCOUNT_EXPIRE, ATTR_ACCOUNT_VALID_FROM};
use kanidm_proto::messages::{AccountChangeMessage, ConsoleOutputMode, MessageStatus};
use time::OffsetDateTime;

use crate::{
    handle_client_error, AccountSsh, AccountUserAuthToken, AccountValidity, OutputMode,
    ServiceAccountApiToken, ServiceAccountCredential, ServiceAccountOpt, ServiceAccountPosix,
};
use time::format_description::well_known::Rfc3339;

impl ServiceAccountOpt {
    pub fn debug(&self) -> bool {
        match self {
            ServiceAccountOpt::Credential { commands } => match commands {
                ServiceAccountCredential::Status(apo) => apo.copt.debug,
                ServiceAccountCredential::GeneratePw(apo) => apo.copt.debug,
            },
            ServiceAccountOpt::ApiToken { commands } => match commands {
                ServiceAccountApiToken::Status(apo) => apo.copt.debug,
                ServiceAccountApiToken::Generate { copt, .. } => copt.debug,
                ServiceAccountApiToken::Destroy { copt, .. } => copt.debug,
            },
            ServiceAccountOpt::Posix { commands } => match commands {
                ServiceAccountPosix::Show(apo) => apo.copt.debug,
                ServiceAccountPosix::Set(apo) => apo.copt.debug,
            },
            ServiceAccountOpt::Session { commands } => match commands {
                AccountUserAuthToken::Status(apo) => apo.copt.debug,
                AccountUserAuthToken::Destroy { copt, .. } => copt.debug,
            },
            ServiceAccountOpt::Ssh { commands } => match commands {
                AccountSsh::List(ano) => ano.copt.debug,
                AccountSsh::Add(ano) => ano.copt.debug,
                AccountSsh::Delete(ano) => ano.copt.debug,
            },
            ServiceAccountOpt::List(copt) => copt.debug,
            ServiceAccountOpt::Get(aopt) => aopt.copt.debug,
            ServiceAccountOpt::Update(aopt) => aopt.copt.debug,
            ServiceAccountOpt::Delete(aopt) => aopt.copt.debug,
            ServiceAccountOpt::Create { copt, .. } => copt.debug,
            ServiceAccountOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => ano.copt.debug,
                AccountValidity::ExpireAt(ano) => ano.copt.debug,
                AccountValidity::BeginFrom(ano) => ano.copt.debug,
            },
            ServiceAccountOpt::IntoPerson(aopt) => aopt.copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            ServiceAccountOpt::Credential { commands } => match commands {
                ServiceAccountCredential::Status(apo) => {
                    let client = apo.copt.to_client(OpType::Read).await;
                    match client
                        .idm_service_account_get_credential_status(apo.aopts.account_id.as_str())
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
                ServiceAccountCredential::GeneratePw(apo) => {
                    let client = apo.copt.to_client(OpType::Write).await;
                    match client
                        .idm_service_account_generate_password(apo.aopts.account_id.as_str())
                        .await
                    {
                        Ok(new_pw) => {
                            println!("Success: {}", new_pw);
                        }
                        Err(e) => {
                            error!("Error generating service account credential -> {:?}", e);
                        }
                    }
                }
            }, // End ServiceAccountOpt::Credential
            ServiceAccountOpt::ApiToken { commands } => match commands {
                ServiceAccountApiToken::Status(apo) => {
                    let client = apo.copt.to_client(OpType::Read).await;
                    match client
                        .idm_service_account_list_api_token(apo.aopts.account_id.as_str())
                        .await
                    {
                        Ok(tokens) => {
                            if tokens.is_empty() {
                                println!("No api tokens exist");
                            } else {
                                for token in tokens {
                                    println!("token: {}", token);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error listing service account api tokens -> {:?}", e);
                        }
                    }
                }
                ServiceAccountApiToken::Generate {
                    aopts,
                    copt,
                    label,
                    expiry,
                    read_write,
                } => {
                    let expiry_odt = if let Some(t) = expiry {
                        // Convert the time to local timezone.
                        match OffsetDateTime::parse(t, &Rfc3339).map(|odt| {
                            odt.to_offset(
                                time::UtcOffset::local_offset_at(OffsetDateTime::UNIX_EPOCH)
                                    .unwrap_or(time::UtcOffset::UTC),
                            )
                        }) {
                            Ok(odt) => {
                                debug!("valid until: {}", odt);
                                Some(odt)
                            }
                            Err(e) => {
                                error!("Error parsing expiry (input: {t:?}) -> {:?}", e);
                                return;
                            }
                        }
                    } else {
                        None
                    };

                    let client = copt.to_client(OpType::Write).await;

                    match client
                        .idm_service_account_generate_api_token(
                            aopts.account_id.as_str(),
                            label,
                            expiry_odt,
                            *read_write,
                        )
                        .await
                    {
                        Ok(new_token) => match copt.output_mode {
                            OutputMode::Json => {
                                let message = AccountChangeMessage {
                                    output_mode: ConsoleOutputMode::JSON,
                                    action: "api-token generate".to_string(),
                                    result: new_token,
                                    status: kanidm_proto::messages::MessageStatus::Success,
                                    src_user: copt
                                        .username
                                        .clone()
                                        .unwrap_or("<unknown username>".to_string()),
                                    dest_user: aopts.account_id.clone(),
                                };
                                println!("{}", message);
                            }
                            OutputMode::Text => {
                                println!("Success: This token will only be displayed ONCE");
                                println!("{}", new_token)
                            }
                        },
                        Err(e) => {
                            error!("Error generating service account api token -> {:?}", e);
                        }
                    }
                }
                ServiceAccountApiToken::Destroy {
                    aopts,
                    copt,
                    token_id,
                } => {
                    let client = copt.to_client(OpType::Write).await;
                    match client
                        .idm_service_account_destroy_api_token(aopts.account_id.as_str(), *token_id)
                        .await
                    {
                        Ok(()) => {
                            println!("Success");
                        }
                        Err(e) => {
                            error!("Error destroying service account token -> {:?}", e);
                        }
                    }
                }
            }, // End ServiceAccountOpt::ApiToken
            ServiceAccountOpt::Posix { commands } => match commands {
                ServiceAccountPosix::Show(aopt) => {
                    let client = aopt.copt.to_client(OpType::Read).await;
                    match client
                        .idm_account_unix_token_get(aopt.aopts.account_id.as_str())
                        .await
                    {
                        Ok(token) => println!("{}", token),
                        Err(e) => handle_client_error(e, aopt.copt.output_mode),
                    }
                }
                ServiceAccountPosix::Set(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_service_account_unix_extend(
                            aopt.aopts.account_id.as_str(),
                            aopt.gidnumber,
                            aopt.shell.as_deref(),
                        )
                        .await
                    {
                        handle_client_error(e, aopt.copt.output_mode)
                    }
                }
            }, // end ServiceAccountOpt::Posix
            ServiceAccountOpt::Session { commands } => match commands {
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
                        Err(e) => {
                            error!("Error listing sessions -> {:?}", e);
                        }
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
                            error!("Error destroying account session -> {:?}", e);
                        }
                    }
                }
            }, // End ServiceAccountOpt::Session
            ServiceAccountOpt::Ssh { commands } => match commands {
                AccountSsh::List(aopt) => {
                    let client = aopt.copt.to_client(OpType::Read).await;

                    match client
                        .idm_account_get_ssh_pubkeys(aopt.aopts.account_id.as_str())
                        .await
                    {
                        Ok(pkeys) => pkeys.iter().for_each(|pkey| println!("{}", pkey)),
                        Err(e) => handle_client_error(e, aopt.copt.output_mode),
                    }
                }
                AccountSsh::Add(aopt) => {
                    let client = aopt.copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_service_account_post_ssh_pubkey(
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
                        .idm_service_account_delete_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                        )
                        .await
                    {
                        handle_client_error(e, aopt.copt.output_mode)
                    }
                }
            }, // end ServiceAccountOpt::Ssh
            ServiceAccountOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_service_account_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            ServiceAccountOpt::Update(aopt) => {
                let client = aopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_service_account_update(
                        aopt.aopts.account_id.as_str(),
                        aopt.newname.as_deref(),
                        aopt.displayname.as_deref(),
                        aopt.entry_managed_by.as_deref(),
                        aopt.mail.as_deref(),
                    )
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, aopt.copt.output_mode),
                }
            }
            ServiceAccountOpt::Get(aopt) => {
                let client = aopt.copt.to_client(OpType::Read).await;
                let res = client
                    .idm_service_account_get(aopt.aopts.account_id.as_str())
                    .await;
                match res {
                    Ok(Some(e)) => aopt.copt.output_mode.print_message(e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, aopt.copt.output_mode),
                }
            }
            ServiceAccountOpt::Delete(aopt) => {
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
                    .idm_service_account_delete(aopt.aopts.account_id.as_str())
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
            ServiceAccountOpt::Create {
                aopts,
                copt,
                display_name,
                entry_managed_by,
            } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_service_account_create(
                        aopts.account_id.as_str(),
                        display_name.as_str(),
                        entry_managed_by.as_str(),
                    )
                    .await
                {
                    handle_client_error(e, copt.output_mode)
                }
            }
            ServiceAccountOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => {
                    let client = ano.copt.to_client(OpType::Read).await;

                    let entry = match client
                        .idm_service_account_get(ano.aopts.account_id.as_str())
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
                        println!("expire: {:?}", t);
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
                                .idm_service_account_purge_attr(
                                    ano.aopts.account_id.as_str(),
                                    ATTR_ACCOUNT_EXPIRE,
                                )
                                .await
                        }
                        Some(new_expiry) => {
                            client
                                .idm_service_account_set_attr(
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
                            .idm_service_account_purge_attr(
                                ano.aopts.account_id.as_str(),
                                ATTR_ACCOUNT_VALID_FROM,
                            )
                            .await
                        {
                            Err(e) => handle_client_error(e, ano.copt.output_mode),
                            _ => println!("Success"),
                        }
                    } else {
                        // Attempt to parse and set
                        if let Err(e) = OffsetDateTime::parse(ano.datetime.as_str(), &Rfc3339) {
                            error!("Error -> {:?}", e);
                            return;
                        }

                        match client
                            .idm_service_account_set_attr(
                                ano.aopts.account_id.as_str(),
                                ATTR_ACCOUNT_VALID_FROM,
                                &[ano.datetime.as_str()],
                            )
                            .await
                        {
                            Err(e) => handle_client_error(e, ano.copt.output_mode),
                            _ => println!("Success"),
                        }
                    }
                }
            }, // end ServiceAccountOpt::Validity
            ServiceAccountOpt::IntoPerson(aopt) => {
                warn!("This command is deprecated and will be removed in a future release");
                let client = aopt.copt.to_client(OpType::Write).await;
                match client
                    .idm_service_account_into_person(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, aopt.copt.output_mode),
                }
            }
        }
    }
}
