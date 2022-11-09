use crate::SynchOpt;

impl SynchOpt {
    pub fn debug(&self) -> bool {
        match self {
            SynchOpt::List(copt) => copt.debug,
            SynchOpt::Get(nopt) => nopt.copt.debug,
            SynchOpt::Create { copt, .. }
            | SynchOpt::GenerateToken { copt, .. }
            | SynchOpt::DestroyToken { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            SynchOpt::List(copt) => {
                let client = copt.to_client().await;
                match client.idm_sync_account_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            SynchOpt::Get(nopt) => {
                let client = nopt.copt.to_client().await;
                match client.idm_sync_account_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            SynchOpt::Create {
                account_id,
                copt,
                description,
            } => {
                let client = copt.to_client().await;
                match client
                    .idm_sync_account_create(&account_id, description.as_deref())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            SynchOpt::GenerateToken {
                account_id,
                label,
                copt,
            } => {
                let client = copt.to_client().await;
                match client
                    .idm_sync_account_generate_token(&account_id, &label)
                    .await
                {
                    Ok(token) => println!("token: {}", token),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            SynchOpt::DestroyToken { account_id, copt } => {
                let client = copt.to_client().await;
                match client.idm_sync_account_destroy_token(&account_id).await {
                    Ok(()) => println!("Success"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
        }
    }
}
