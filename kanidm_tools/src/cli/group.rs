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
            GroupOpt::Posix(gpopt) => match gpopt {
                GroupPosix::Show(gcopt) => gcopt.copt.debug,
                GroupPosix::Set(gcopt) => gcopt.copt.debug,
            },
        }
    }

    pub fn exec(&self) {
        match self {
            GroupOpt::List(copt) => {
                let client = copt.to_client();
                match client.idm_group_list() {
                    Ok(r) => r.iter().for_each(|ent| info!("{}", ent)),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            GroupOpt::Get(gcopt) => {
                let client = gcopt.copt.to_client();
                // idm_group_get
                match client.idm_group_get(gcopt.name.as_str()) {
                    Ok(Some(e)) => info!("{}", e),
                    Ok(None) => info!("No matching group '{}'", gcopt.name.as_str()),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            GroupOpt::Create(gcopt) => {
                let client = gcopt.copt.to_client();
                match client.idm_group_create(gcopt.name.as_str()) {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => info!("Successfully created group '{}'", gcopt.name.as_str()),
                }
            }
            GroupOpt::Delete(gcopt) => {
                let client = gcopt.copt.to_client();
                match client.idm_group_delete(gcopt.name.as_str()) {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => info!("Successfully deleted group {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                match client.idm_group_purge_members(gcopt.name.as_str()) {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => info!(
                        "Successfully purged members of group {}",
                        gcopt.name.as_str()
                    ),
                }
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                match client.idm_group_get_members(gcopt.name.as_str()) {
                    Ok(Some(groups)) => groups.iter().for_each(|m| info!("{:?}", m)),
                    Ok(None) => info!("No members in group {}", gcopt.name.as_str()),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client.idm_group_add_members(gcopt.name.as_str(), &new_members) {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => info!("Successfully added members to {}", gcopt.name.as_str()),
                }
            }

            GroupOpt::RemoveMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let remove_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client.idm_group_remove_members(gcopt.name.as_str(), &remove_members) {
                    Err(e) => error!("Failed to remove members -> {:?}", e),
                    Ok(_) => info!("Successfully removed members from {}", gcopt.name.as_str()),
                }
            }

            GroupOpt::SetMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client.idm_group_set_members(gcopt.name.as_str(), &new_members) {
                    Err(e) => error!("Error -> {:?}", e),
                    Ok(_) => info!("Successfully set members for group {}", gcopt.name.as_str()),
                }
            }
            GroupOpt::Posix(gpopt) => match gpopt {
                GroupPosix::Show(gcopt) => {
                    let client = gcopt.copt.to_client();
                    match client.idm_group_unix_token_get(gcopt.name.as_str()) {
                        Ok(token) => info!("{}", token),
                        Err(e) => error!("Error -> {:?}", e),
                    }
                }
                GroupPosix::Set(gcopt) => {
                    let client = gcopt.copt.to_client();
                    match client.idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber) {
                        Err(e) => error!("Error -> {:?}", e),
                        Ok(_) => info!(
                            "Success adding POSIX configuration for group {}",
                            gcopt.name.as_str()
                        ),
                    }
                }
            },
        } // end match
    }
}
