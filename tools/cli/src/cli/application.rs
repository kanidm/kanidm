use crate::common::OpType;
use crate::handle_client_error;
use crate::ApplicationOpt;

impl ApplicationOpt {
    pub fn debug(&self) -> bool {
        match self {
            ApplicationOpt::List(copt) => copt.debug,
            ApplicationOpt::Create(nopt) => nopt.copt.debug,
            ApplicationOpt::Delete(nopt) => nopt.copt.debug,
            ApplicationOpt::AddMembers(gcopt) => gcopt.copt.debug,
            ApplicationOpt::ListMembers(gcopt) => gcopt.copt.debug,
            ApplicationOpt::RemoveMembers(gcopt) => gcopt.copt.debug,
            ApplicationOpt::PurgeMembers(gcopt) => gcopt.copt.debug,
        }
    }
    pub async fn exec(&self) {
        match self {
            ApplicationOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_application_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            ApplicationOpt::Create(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client.idm_application_create(nopt.name.as_str()).await {
                    Ok(_) => println!("Application {} successfully created.", &nopt.name),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            ApplicationOpt::Delete(nopt) => {
                let client = nopt.copt.to_client(OpType::Write).await;
                match client.idm_application_delete(nopt.name.as_str()).await {
                    Ok(_) => println!("Application {} successfully deleted.", &nopt.name),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            ApplicationOpt::AddMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                let new_members: Vec<&str> = gcopt.members.iter().map(String::as_str).collect();

                match client
                    .idm_application_add_members(gcopt.name.as_str(), &new_members)
                    .await
                {
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    Ok(_) => println!(
                        "Successfully added {:?} to application \"{}\"",
                        &new_members,
                        gcopt.name.as_str()
                    ),
                }
            }
            ApplicationOpt::ListMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Read).await;
                match client
                    .idm_application_get_members(gcopt.name.as_str())
                    .await
                {
                    Ok(Some(members)) => members.iter().for_each(|m| println!("{:?}", m)),
                    Ok(None) => warn!("No members in application {}", gcopt.name.as_str()),
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                }
            }
            ApplicationOpt::RemoveMembers(gcopt) => {
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
            ApplicationOpt::PurgeMembers(gcopt) => {
                let client = gcopt.copt.to_client(OpType::Write).await;
                match client.idm_group_purge_members(gcopt.name.as_str()).await {
                    Err(e) => handle_client_error(e, gcopt.copt.output_mode),
                    Ok(_) => println!(
                        "Successfully purged members of application {}",
                        gcopt.name.as_str()
                    ),
                }
            }
        }
    }
}
