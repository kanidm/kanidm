use crate::{GroupOpt, GroupPosix};

impl GroupOpt {
    pub fn debug(&self) -> bool {
        match self {
            GroupOpt::List(copt) => copt.debug,
            GroupOpt::Get(gcopt) => gcopt.copt.debug,
            GroupOpt::Create(gcopt) => gcopt.copt.debug,
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
        }
    }

    pub async fn exec(&self) {
        match self {
            GroupOpt::List(copt) => {
                let client = copt.to_client().await;
                match client.idm_group_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            GroupOpt::Get(gcopt) => {
                let client = gcopt.copt.to_client().await;
                // idm_group_get
                match client.idm_group_get(gcopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => warn!("No matching group '{}'", gcopt.name.as_str()),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            GroupOpt::Create(gcopt) => {
                let client = gcopt.copt.to_client().await;
                match client.idm_group_create(gcopt.name.as_str()).await {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => println!("Successfully created group '{}'", gcopt.name.as_str()),
                }
            }
            GroupOpt::Delete(gcopt) => {
                let client = gcopt.copt.to_client().await;
                match client.idm_group_delete(gcopt.name.as_str()).await {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => println!("Successfully deleted group {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = gcopt.copt.to_client().await;
                match client.idm_group_purge_members(gcopt.name.as_str()).await {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => println!(
                        "Successfully purged members of group {}",
                        gcopt.name.as_str()
                    ),
                }
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = gcopt.copt.to_client().await;
                match client.idm_group_get_members(gcopt.name.as_str()).await {
                    Ok(Some(groups)) => groups.iter().for_each(|m| println!("{:?}", m)),
                    Ok(None) => warn!("No members in group {}", gcopt.name.as_str()),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = gcopt.copt.to_client().await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_add_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => println!(
                        "Successfully added {:?} to group \"{}\"",
                        &new_members,
                        gcopt.name.as_str()
                    ),
                }
            }

            GroupOpt::RemoveMembers(gcopt) => {
                let client = gcopt.copt.to_client().await;
                let remove_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_remove_members(gcopt.name.as_str(), &remove_members)
                    .await
                {
                    Err(e) => error!("Failed to remove members -> {:?}", e),
                    Ok(_) => println!("Successfully removed members from {}", gcopt.name.as_str()),
                }
            }

            GroupOpt::SetMembers(gcopt) => {
                let client = gcopt.copt.to_client().await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_group_set_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => println!("Successfully set members for group {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::Posix { commands } => match commands {
                GroupPosix::Show(gcopt) => {
                    let client = gcopt.copt.to_client().await;
                    match client.idm_group_unix_token_get(gcopt.name.as_str()).await {
                        Ok(token) => println!("{}", token),
                        Err(e) => error!("Error -> {:?}", e),
                    }
                }
                GroupPosix::Set(gcopt) => {
                    let client = gcopt.copt.to_client().await;
                    match client
                        .idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber)
                        .await
                    {
                        Err(e) => error!("Error -> {:?}", e),
                        Ok(_) => println!(
                            "Success adding POSIX configuration for group {}",
                            gcopt.name.as_str()
                        ),
                    }
                }
            },
        } // end match
    }
}
