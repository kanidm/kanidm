use crate::{handle_client_error, GroupOpt, GroupPosix, KanidmClientParser, OutputMode};
use kanidm_proto::cli::OpType;
use kanidm_proto::constants::ATTR_GIDNUMBER;

mod account_policy;

impl GroupOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            GroupOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_group_list().await {
                    Ok(r) => match opt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{ent}")),
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::Search { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_group_search(name).await {
                    Ok(r) => match opt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{ent}")),
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::Get(gcopt) => {
                let client = opt.to_client(OpType::Read).await;
                // idm_group_get
                match client.idm_group_get(gcopt.name.as_str()).await {
                    Ok(Some(e)) => opt.output_mode.print_message(e),
                    Ok(None) => opt
                        .output_mode
                        .print_message(format!("No matching group '{}'", gcopt.name.as_str())),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::Create {
                name,
                entry_managed_by,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_group_create(name.as_str(), entry_managed_by.as_deref())
                    .await
                {
                    Err(err) => {
                        error!("Error -> {:?}", err)
                    }
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("Successfully created group '{}'", name.as_str())),
                }
            }
            GroupOpt::Delete(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_group_delete(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully deleted group {}",
                        gcopt.name.as_str()
                    )),
                }
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_group_purge_members(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully purged members of group {}",
                        gcopt.name.as_str()
                    )),
                }
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_group_get_members(gcopt.name.as_str()).await {
                    Ok(Some(groups)) => match opt.output_mode {
                        OutputMode::Json => {
                            println!(
                                "{}",
                                serde_json::to_string(&groups)
                                    .expect("Failed to serialise groups to JSON")
                            );
                        }
                        OutputMode::Text => groups.iter().for_each(|m| println!("{m:?}")),
                    },
                    Ok(None) => warn!("No members in group {}", gcopt.name.as_str()),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_add_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully added {:?} to group \"{}\"",
                        &new_members,
                        gcopt.name.as_str()
                    )),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            GroupOpt::RemoveMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                let remove_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_remove_members(gcopt.name.as_str(), &remove_members)
                    .await
                {
                    Err(e) => {
                        error!("Failed to remove members!");
                        handle_client_error(e, opt.output_mode)
                    }
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully removed members from group {}",
                        gcopt.name
                    )),
                }
            }
            GroupOpt::SetMembers(gcopt) => {
                let client = opt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_set_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set members for group {}",
                        gcopt.name
                    )),
                }
            }
            GroupOpt::SetMail { name, mail } => {
                let client = opt.to_client(OpType::Write).await;

                let result = if mail.is_empty() {
                    client.idm_group_purge_mail(name.as_str()).await
                } else {
                    client
                        .idm_group_set_mail(name.as_str(), mail.as_slice())
                        .await
                };

                match result {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set mail for group {}",
                        name.as_str()
                    )),
                }
            }
            GroupOpt::SetDescription { name, description } => {
                let client = opt.to_client(OpType::Write).await;

                let result = if let Some(description) = description {
                    client
                        .idm_group_set_description(name.as_str(), description.as_str())
                        .await
                } else {
                    client.idm_group_purge_description(name.as_str()).await
                };

                match result {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set description for group {}",
                        name.as_str()
                    )),
                }
            }
            GroupOpt::Rename { name, new_name } => {
                let client = opt.to_client(OpType::Write).await;

                let result = client.group_rename(name.as_str(), new_name.as_str()).await;

                match result {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("Successfully renamed group {name} to {new_name}")),
                }
            }
            GroupOpt::SetEntryManagedBy {
                name,
                entry_managed_by,
            } => {
                let client = opt.to_client(OpType::Write).await;

                match client
                    .idm_group_set_entry_managed_by(name, entry_managed_by)
                    .await
                {
                    Err(e) => handle_client_error(e, opt.output_mode),
                    Ok(_) => opt.output_mode.print_message(format!(
                        "Successfully set entry manager to '{entry_managed_by}' for group '{name}'"
                    )),
                }
            }
            GroupOpt::Posix { commands } => match commands {
                GroupPosix::Show(gcopt) => {
                    let client = opt.to_client(OpType::Read).await;
                    match client.idm_group_unix_token_get(gcopt.name.as_str()).await {
                        Ok(token) => opt.output_mode.print_message(token),
                        Err(e) => handle_client_error(e, opt.output_mode),
                    }
                }
                GroupPosix::Set(gcopt) => {
                    let client = opt.to_client(OpType::Write).await;
                    match client
                        .idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber)
                        .await
                    {
                        Err(e) => handle_client_error(e, opt.output_mode),
                        Ok(_) => opt.output_mode.print_message(format!(
                            "Success adding POSIX configuration for group {}",
                            gcopt.name
                        )),
                    }
                }
                GroupPosix::ResetGidnumber { group_id } => {
                    let client = opt.to_client(OpType::Write).await;
                    if let Err(e) = client
                        .idm_group_purge_attr(group_id.as_str(), ATTR_GIDNUMBER)
                        .await
                    {
                        handle_client_error(e, opt.output_mode)
                    }
                }
            },
            GroupOpt::AccountPolicy { commands } => commands.exec(opt).await,
        } // end match
    }
}
