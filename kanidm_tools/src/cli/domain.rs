use crate::DomainOpt;

impl DomainOpt {
    pub fn debug(&self) -> bool {
        match self {
            DomainOpt::Show(copt) | DomainOpt::ResetTokenKey(copt) => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            DomainOpt::Show(copt) => {
                let client = copt.to_client().await;
                match client.idm_domain_get().await {
                    Ok(e) => println!("{}", e),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
            DomainOpt::ResetTokenKey(copt) => {
                let client = copt.to_client().await;
                match client.idm_domain_reset_token_key().await {
                    Ok(_) => println!("Success"),
                    Err(e) => error!("Error -> {:?}", e),
                }
            }
        }
    }
}
