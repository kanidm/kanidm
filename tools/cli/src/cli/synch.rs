use crate::{handle_client_error, KanidmClientParser, SynchOpt};
use dialoguer::Confirm;
use kanidm_proto::cli::OpType;

impl SynchOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            SynchOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_sync_account_list().await {
                    Ok(r) => r.iter().for_each(|ent| println!("{ent}")),

                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::Get(nopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_sync_account_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => println!("{e}"),
                    Ok(None) => println!("No matching entries"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::SetCredentialPortal { account_id, url } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_set_credential_portal(account_id, url.as_ref())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::Create {
                account_id,
                description,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_create(account_id, description.as_deref())
                    .await
                {
                    Ok(()) => println!("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::GenerateToken { account_id, label } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_generate_token(account_id, label)
                    .await
                {
                    Ok(token) => println!("token: {token}"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::DestroyToken { account_id } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_sync_account_destroy_token(account_id).await {
                    Ok(()) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::SetYieldAttributes { account_id, attrs } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_sync_account_set_yield_attributes(account_id, attrs)
                    .await
                {
                    Ok(()) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::ForceRefresh { account_id } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_sync_account_force_refresh(account_id).await {
                    Ok(()) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::Finalise { account_id } => {
                if !Confirm::new()
                    .default(false)
                    .with_prompt("Do you want to continue? This operation can NOT be undone.")
                    .interact()
                    .expect("Failed to get a valid response!")
                {
                    opt.output_mode.print_message("No changes were made");
                    return;
                }

                let client = opt.to_client(OpType::Write).await;
                match client.idm_sync_account_finalise(account_id).await {
                    Ok(()) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SynchOpt::Terminate { account_id } => {
                if !Confirm::new()
                    .default(false)
                    .with_prompt("Do you want to continue? This operation can NOT be undone.")
                    .interact()
                    .expect("Failed to get a valid response!")
                {
                    opt.output_mode.print_message("No changes were made");
                    return;
                }

                let client = opt.to_client(OpType::Write).await;
                match client.idm_sync_account_terminate(account_id).await {
                    Ok(()) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
