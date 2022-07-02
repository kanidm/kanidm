use crate::DomainOpt;

impl DomainOpt {
    pub fn debug(&self) -> bool {
        match self {
            DomainOpt::SetDomainDisplayName(copt) => copt.copt.debug,
            DomainOpt::Show(copt) |
            DomainOpt::ResetTokenKey(copt)
                => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            DomainOpt::SetDomainDisplayName(opt) => {
                eprintln!("Attempting to set the domain's display name to: {:?}", opt.new_display_name);
                let client = opt.copt.to_client().await;
                match client.idm_domain_set_display_name(opt.new_display_name.clone()).await {
                    Ok(result) => println!("{}", result),
                    Err(e) => eprintln!("{:?}", e)
                }
            }
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
