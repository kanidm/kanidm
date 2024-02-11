use std::collections::HashSet;
use std::future::join;
use kanidm_client::ClientError;
use kanidm_proto::v1::Entry;
use crate::common::OpType;
use crate::{handle_client_error, GroupOpt, GroupPosix, OutputMode, ObjectType};

mod account_policy;

impl GroupOpt {
    pub fn debug(&self) -> bool {
        match self {
            GroupOpt::List(copt) => copt.debug,
            GroupOpt::Graph(gopt) => gopt.copt.debug,
            GroupOpt::Get(gcopt) => gcopt.copt.debug,
            GroupOpt::SetEntryManagedBy { copt, .. } | GroupOpt::Create { copt, .. } => copt.debug,
            GroupOpt::Delete(gcopt) => gcopt.copt.debug,
            GroupOpt::ListMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::AddMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::RemoveMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::SetMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::PurgeMembers(gcopt) => gcopt.copt.debug,
            GroupOpt::Posix { commands } => match commands {
                GroupPosix::Show(gcopt) => gcopt.copt.debug,
                GroupPosix::Set(gcopt) => gcopt.copt.debug,
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
            GroupOpt::Graph(gopt) => {
                let copt = &gopt.copt;
                let client = copt.to_client(OpType::Read).await;
                let graph_type = &gopt.graph_type;
                let filters = &gopt.filter;

                println!("{graph_type:?} {filters:?}");
                let arr_result: [Result<Vec<Entry>, ClientError>; 3] = join!(client.idm_group_list(), client.idm_service_account_list(), client.idm_person_account_list()).await
                    .into();
                let list_result: Result<Vec<Entry>, ClientError> = arr_result
                    .into_iter()
                    .collect::<Result<Vec<_>, _>>()
                    .map(|v| { v.into_iter().flatten().collect() });
                let entries = match list_result {
                    Ok(entries) => entries,
                    Err(e) => {
                        handle_client_error(e, copt.output_mode);
                        return;
                    }
                };


                match copt.output_mode {
                    OutputMode::Json => {
                        let r_attrs: Vec<_> = entries.iter().map(|entry| &entry.attrs).collect();
                        println!(
                            "{}",
                            serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                        );
                    }
                    OutputMode::Text => {
                        let typed_entries = entries.iter()
                            .filter_map(|entry| {
                                let classes = entry.attrs.get("class")?;

                                // Logic to decide the type of each entry
                                let obj_type = if classes.contains(&"group".to_string()) {
                                    let uuid = entry.attrs.get("uuid")?.first()?;
                                    let description = entry.attrs.get("description")?.first()?;

                                    if description.starts_with("Builtin ") || uuid.starts_with("00000000-0000-0000-0000-") {
                                        ObjectType::BuiltinGroup
                                    } else {
                                        ObjectType::Group
                                    }
                                } else if classes.contains(&"account".to_string()) {
                                    if classes.contains(&"person".to_string()) {
                                        ObjectType::Person
                                    } else {
                                        ObjectType::ServiceAccount
                                    }
                                } else {
                                    return None;
                                };

                                // filter out the things we want to keep, if the filter is empty we assume we want all.
                                if !filters.contains(&obj_type) && !filters.is_empty() {
                                    return None;
                                }

                                let name = entry.attrs.get("name")?.first()?;
                                Some((name.clone(), obj_type))
                            }).collect::<HashSet<(String, ObjectType)>>();

                        // Vec<obj, obj's members>
                        let members_of = entries.into_iter().filter_map(|entry| {
                            let name = entry.attrs.get("name")?.first()?.clone();
                            // if !typed_entries.contains(&(name.clone(), ObjectType::Group)) { return None; }

                            Some((name, entry.attrs.get("member")?.clone()))
                        }).collect::<Vec<_>>();

                        // Printing of the graph
                        println!("graph RL");
                        for (name, members) in members_of {
                            members.iter()
                                .map(|member| member.trim_end_matches("@idm.melijn.com"))
                                // .filter(|member| groups.contains(*member))
                                .for_each(|member| {
                                    println!("  {name}[\"{name}\"] --> {member}[\"{member}\"]")
                                });
                        }
                        println!("  classDef groupClass fill:#f9f,stroke:#333,stroke-width:4px,stroke-dasharray: 5 5");
                        println!("  classDef builtInGroupClass fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff,stroke-dasharray: 5 5");
                        println!("  classDef serviceAccountClass fill:#f9f,stroke:#333,stroke-width:4px");
                        println!("  classDef personClass fill:#bbf,stroke:#f66,stroke-width:2px,color:#fff");

                        for (name, obj_type) in typed_entries {
                            let class = match obj_type {
                                ObjectType::Group => "groupClass",
                                ObjectType::BuiltinGroup => "builtInGroupClass",
                                ObjectType::ServiceAccount => "serviceAccountClass",
                                ObjectType::Person => "personClass",
                            };
                            println!("  {name}[\"{name}\"]");
                            println!("  class {name} {class}");
                        }
                    }
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
            },
            GroupOpt::AccountPolicy { commands } => commands.exec().await,
        } // end match
    }
}
