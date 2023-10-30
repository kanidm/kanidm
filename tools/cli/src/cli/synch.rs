use crate::common::OpType;
use crate::{handle_client_error, SynchOpt};
use dialoguer::Confirm;

impl SynchOpt {
    pub fn debug(&self) -> bool {
        match self {
            SynchOpt::List(copt) => copt.debug,
            SynchOpt::Get(nopt) => nopt.copt.debug,
            SynchOpt::Create { copt, .. }
            | SynchOpt::GenerateToken { copt, .. }
            | SynchOpt::DestroyToken { copt, .. }
            | SynchOpt::ForceRefresh { copt, .. }
            | SynchOpt::Finalise { copt, .. }
            | SynchOpt::Terminate { copt, .. }
            | SynchOpt::SetYieldAttributes { copt, .. }
            | SynchOpt::SetCredentialPortal { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            SynchOpt::List(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_sync_account_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{}", ent)),

                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::Get(nopt) => {
                let client = nopt.copt.to_client(OpType::Read).await;
                match client.idm_sync_account_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{}", e),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, nopt.copt.output_mode),
                }
            }
            SynchOpt::SetCredentialPortal {
                account_id,
                copt,
                url,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_set_credential_portal(account_id, url.as_ref())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::Create {
                account_id,
                copt,
                description,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_create(account_id, description.as_deref())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::GenerateToken {
                account_id,
                label,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_generate_token(account_id, label)
                    .await
                {
                    Ok(token) => println!("token: {}", token),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::DestroyToken { account_id, copt } => {
                let client = copt.to_client(OpType::Write).await;
                match client.idm_sync_account_destroy_token(account_id).await {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::SetYieldAttributes {
                account_id,
                copt,
                attrs,
            } => {
                let client = copt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_set_yield_attributes(account_id, attrs)
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::ForceRefresh { account_id, copt } => {
                let client = copt.to_client(OpType::Write).await;
                match client.idm_sync_account_force_refresh(account_id).await {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::Finalise { account_id, copt } => {
                if !Confirm::new()
                    .default(false)
                    .with_prompt("Do you want to continue? This operation can NOT be undone.")
                    .interact()
                    .expect("Failed to get a valid response!")
                {
                    info!("No changes were made");
                    return;
                }

                let client = copt.to_client(OpType::Write).await;
                match client.idm_sync_account_finalise(account_id).await {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
            SynchOpt::Terminate { account_id, copt } => {
                if !Confirm::new()
                    .default(false)
                    .with_prompt("Do you want to continue? This operation can NOT be undone.")
                    .interact()
                    .expect("Failed to get a valid response!")
                {
                    info!("No changes were made");
                    return;
                }

                let client = copt.to_client(OpType::Write).await;
                match client.idm_sync_account_terminate(account_id).await {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, copt.output_mode),
                }
            }
        }
    }
}
