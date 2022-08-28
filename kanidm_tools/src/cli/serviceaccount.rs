use crate::{AccountSsh, AccountValidity, ServiceAccountOpt, ServiceAccountPosix};
use kanidm_proto::messages::{AccountChangeMessage, ConsoleOutputMode, MessageStatus};
use time::OffsetDateTime;

impl ServiceAccountOpt {
    pub fn debug(&self) -> bool {
        match self {
            ServiceAccountOpt::Posix { commands } => match commands {
                ServiceAccountPosix::Show(apo) => apo.copt.debug,
                ServiceAccountPosix::Set(apo) => apo.copt.debug,
            },
            ServiceAccountOpt::Ssh { commands } => match commands {
                AccountSsh::List(ano) => ano.copt.debug,
                AccountSsh::Add(ano) => ano.copt.debug,
                AccountSsh::Delete(ano) => ano.copt.debug,
            },
            ServiceAccountOpt::List(copt) => copt.debug,
            ServiceAccountOpt::Get(aopt) => aopt.copt.debug,
            ServiceAccountOpt::Delete(aopt) => aopt.copt.debug,
            ServiceAccountOpt::Create(aopt) => aopt.copt.debug,
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
            ServiceAccountOpt::Posix { commands } => match commands {
                ServiceAccountPosix::Show(aopt) => {
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
                ServiceAccountPosix::Set(aopt) => {
                    let client = aopt.copt.to_client().await;
                    if let Err(e) = client
                        .idm_service_account_unix_extend(
                            aopt.aopts.account_id.as_str(),
                            aopt.gidnumber,
                            aopt.shell.as_deref(),
                        )
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
            }, // end ServiceAccountOpt::Posix
            ServiceAccountOpt::Ssh { commands } => match commands {
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
                        .idm_service_account_post_ssh_pubkey(
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
                        .idm_service_account_delete_ssh_pubkey(
                            aopt.aopts.account_id.as_str(),
                            aopt.tag.as_str(),
                        )
                        .await
                    {
                        error!("Error -> {:?}", e);
                    }
                }
            }, // end ServiceAccountOpt::Ssh
            ServiceAccountOpt::List(copt) => {
                let client = copt.to_client().await;
                match client.idm_service_account_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            ServiceAccountOpt::Get(aopt) => {
                let client = aopt.copt.to_client().await;
                match client
                    .idm_service_account_get(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            ServiceAccountOpt::Delete(aopt) => {
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
            ServiceAccountOpt::Create(acopt) => {
                let client = acopt.copt.to_client().await;
                if let Err(e) = client
                    .idm_service_account_create(
                        acopt.aopts.account_id.as_str(),
                        acopt.display_name.as_str(),
                    )
                    .await
                {
                    error!("Error -> {:?}", e)
                }
            }
            ServiceAccountOpt::Validity { commands } => match commands {
                AccountValidity::Show(ano) => {
                    let client = ano.copt.to_client().await;

                    println!("user: {}", ano.aopts.account_id.as_str());
                    let ex = match client
                        .idm_service_account_get_attr(
                            ano.aopts.account_id.as_str(),
                            "account_expire",
                        )
                        .await
                    {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Error -> {:?}", e);
                            return;
                        }
                    };

                    let vf = match client
                        .idm_service_account_get_attr(
                            ano.aopts.account_id.as_str(),
                            "account_valid_from",
                        )
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
                            .idm_service_account_purge_attr(
                                ano.aopts.account_id.as_str(),
                                "account_expire",
                            )
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
                            .idm_service_account_set_attr(
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
                            .idm_service_account_purge_attr(
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
                            .idm_service_account_set_attr(
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
            }, // end ServiceAccountOpt::Validity
            ServiceAccountOpt::IntoPerson(aopt) => {
                let client = aopt.copt.to_client().await;
                match client
                    .idm_service_account_into_person(aopt.aopts.account_id.as_str())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
        }
    }
}
