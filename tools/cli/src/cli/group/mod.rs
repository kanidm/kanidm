use crate::common::OpType;
use crate::{handle_client_error, GroupOpt, GroupPosix, OutputMode};
use kanidm_proto::constants::ATTR_GIDNUMBER;

mod account_policy;

impl GroupOpt {
    pub fn debug(&self) -> bool {
        match self {
            GroupOpt::List(copt) => copt.debug,
            GroupOpt::Get(gcopt) => gcopt.copt.debug,
            GroupOpt::SetEntryManagedBy { copt, .. } | GroupOpt::Create { copt, .. } => copt.debug,
            GroupOpt::Delete(gcopt) => gcopt.copt.debug,
            GroupOpt::ListMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::AddMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::RemoveMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::SetMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::PurgeMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::SetMail { copt, .. } => copt.debug,
            GroupOpt::Posix { commands } => match commands {
                GroupPosix::Show(gcopt) => gcopt.copt.debug,
                GroupPosix::Set(gcopt) => gcopt.copt.debug,
                GroupPosix::ResetGidnumber { copt, .. } => copt.debug,
            },
            GroupOpt::AccountPolicy { commands } => commands.debug(),
        }
    }

    pub async fn exec(&self) {
        match self {
            GroupOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_group_list().await {
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
            GroupOpt::Get(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Read).await;
                // idm_group_get
                match client.idm_group_get(gcopt.name.as_str()).await {
                    Ok(Some(e)) => match gcopt.copt.output_mode {
                        OutputMode::Json => {
                            println!(
                                "{}",
                                serde_json::to_string(&e.attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => println!("{}", e),
                    },
                    Ok(None) => warn!("No matching group '{}'", gcopt.name.as_str()),
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                }
            }
            GroupOpt::Create {
                copt,
                name,
                entry_managed_by,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_group_create(name.as_str(), entry_managed_by.as_deref())
                    .await
                {
                    Err(err) => {
                        error!("Error -> {:?}", err)
                    }
                    Ok(_) => println!("Successfully created group '{}'", name.as_str()),
                }
            }
            GroupOpt::Delete(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                match client.idm_group_delete(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    Ok(_) => println!("Successfully deleted group {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                match client.idm_group_purge_members(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    Ok(_) => println!(
                        "Successfully purged members of group {}",
                        gcopt.name.as_str()
                    ),
                }
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Read).await;
                match client.idm_group_get_members(gcopt.name.as_str()).await {
                    Ok(Some(groups)) => groups.iter().for_each(|m| println!("{:?}", m)),
                    Ok(None) => warn!("No members in group {}", gcopt.name.as_str()),
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_add_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    Ok(_) => println!(
                        "Successfully added {:?} to group \"{}\"",
                        &new_members,
                        gcopt.name.as_str()
                    ),
                }
            }

            GroupOpt::RemoveMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                let remove_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_remove_members(gcopt.name.as_str(), &remove_members)
                    .await
                {
                    Err(e) => {
                        error!("Failed to remove members!");
                        handle_client_error(e, gcopt.copt.output_mode)
                    }
                    Ok(_) => println!("Successfully removed members from {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::SetMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_set_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    Ok(_) => println!("Successfully set members for group {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::SetMail { copt, name, mail } => {
                let client = copt.to_client(OpType::Write).await;

                let result = if mail.is_empty() {
                    client.idm_group_purge_mail(name.as_str()).await
                } else {
                    client
                        .idm_group_set_mail(name.as_str(), mail.as_slice())
                        .await
                };

                match result {
                    Err(e) => handle_client_error(e, copt.output_mode),
                    Ok(_) => println!("Successfully set mail for group {}", name.as_str()),
                }
            }
            GroupOpt::SetEntryManagedBy {
                name,
                entry_managed_by,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;

                match client
                    .idm_group_set_entry_managed_by(name.as_str(), entry_managed_by.as_str())
                    .await
                {
                    Err(e) => handle_client_error(e, copt.output_mode),
                    Ok(_) => println!("Successfully set members for group {}", name.as_str()),
                }
            }
            GroupOpt::Posix { commands } => match commands {
                GroupPosix::Show(gcopt) => {
                    let client = gcopt.copt.to_client(OpType::Read).await;
                    match client.idm_group_unix_token_get(gcopt.name.as_str()).await {
                        Ok(token) => println!("{}", token),
                        Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    }
                }
                GroupPosix::Set(gcopt) => {
                    let client = gcopt.copt.to_client(OpType::Write).await;
                    match client
                        .idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber)
                        .await
                    {
                        Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                        Ok(_) => println!(
                            "Success adding POSIX configuration for group {}",
                            gcopt.name.as_str()
                        ),
                    }
                }
                GroupPosix::ResetGidnumber { copt, group_id } => {
                    let client = copt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_group_purge_attr(group_id.as_str(), ATTR_GIDNUMBER)
                        .await
                    {
                        handle_client_error(e, copt.output_mode)
                    }
                }
            },
            GroupOpt::AccountPolicy { commands } => commands.exec().await,
        } // end match
    }
}
