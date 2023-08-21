use crate::common::OpType;

use crate::{AuthSessionExpiryOpt, PrivilegedSessionExpiryOpt};

impl AuthSessionExpiryOpt {
    pub fn debug(&self) -> bool {
        match self {
            AuthSessionExpiryOpt::Get(copt) => copt.debug,
            AuthSessionExpiryOpt::Set { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            AuthSessionExpiryOpt::Get(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.system_authsession_expiry_get().await {
                    Ok(exp_time) => {
                        println!(
                            "The current system auth session expiry time is: {exp_time} seconds."
                        );
                    }
                    Err(e) => eprintln!("{:?}", e),
                }
            }
            AuthSessionExpiryOpt::Set { copt, expiry } => {
                let client = copt.to_client(OpType::Write).await;
                match client.system_authsession_expiry_set(*expiry).await {
                    Ok(()) => {
                        println!("The system auth session expiry has been successfully updated.")
                    }

                    Err(e) => eprintln!("{:?}", e),
                }
            }
        }
    }
}

impl PrivilegedSessionExpiryOpt {
    pub fn debug(&self) -> bool {
        match self {
            PrivilegedSessionExpiryOpt::Get(copt) => copt.debug,
            PrivilegedSessionExpiryOpt::Set { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            PrivilegedSessionExpiryOpt::Get(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.system_auth_privilege_expiry_get().await {
                    Ok(exp_time) => {
                        println!(
                            "The current system auth privilege expiry time is: {exp_time} seconds."
                        );
                    }
                    Err(e) => eprintln!("{:?}", e),
                }
            }
            PrivilegedSessionExpiryOpt::Set { copt, expiry } => {
                let client = copt.to_client(OpType::Write).await;
                match client.system_auth_privilege_expiry_set(*expiry).await {
                    Ok(()) => {
                        println!("The system auth privilege expiry has been successfully updated.")
                    }

                    Err(e) => eprintln!("{:?}", e),
                }
            }
        }
    }
}
