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
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }
            GroupOpt::Get(gcopt) => {
                let client = gcopt.copt.to_client();
                // idm_group_get
                match client.idm_group_get(gcopt.name.as_str()) {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => eprintln!("Error -> {:?}", e),
                }
            }
            GroupOpt::Create(gcopt) => {
                let client = gcopt.copt.to_client();
                if let Err(e) = client.idm_group_create(gcopt.name.as_str()) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            GroupOpt::Delete(gcopt) => {
                let client = gcopt.copt.to_client();
                if let Err(e) = client.idm_group_delete(gcopt.name.as_str()) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            GroupOpt::PurgeMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                if let Err(e) = client.idm_group_purge_members(gcopt.name.as_str()) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            GroupOpt::ListMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                match client.idm_group_get_members(gcopt.name.as_str()) {
                    Ok(Some(groups)) => groups.iter().for_each(|m| println!("{:?}", m)),
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            }
            GroupOpt::AddMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let new_members: Vec<&str> = gcopt.members.iter().map(|s| s.as_str()).collect();

                if let Err(e) = client.idm_group_add_members(gcopt.name.as_str(), &new_members) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            GroupOpt::SetMembers(gcopt) => {
                let client = gcopt.copt.to_client();
                let new_members: Vec<&str> = gcopt.members.iter().map(|s| s.as_str()).collect();

                if let Err(e) = client.idm_group_set_members(gcopt.name.as_str(), &new_members) {
                    eprintln!("Error -> {:?}", e);
                }
            }
            GroupOpt::Posix(gpopt) => match gpopt {
                GroupPosix::Show(gcopt) => {
                    let client = gcopt.copt.to_client();
                    match client.idm_group_unix_token_get(gcopt.name.as_str()) {
                        Ok(token) => println!("{}", token),
                        Err(e) => eprintln!("Error -> {:?}", e),
                    }
                }
                GroupPosix::Set(gcopt) => {
                    let client = gcopt.copt.to_client();
                    if let Err(e) =
                        client.idm_group_unix_extend(gcopt.name.as_str(), gcopt.gidnumber)
                    {
                        eprintln!("Error -> {:?}", e);
                    }
                }
            },
        } // end match
    }
}
