use crate::common::OpType;
use crate::{handle_client_error, GroupAccountPolicyOpt};

impl GroupAccountPolicyOpt {
    pub fn debug(&self) -> bool {
        match self {
            GroupAccountPolicyOpt::Enable { copt, .. }
            | GroupAccountPolicyOpt::AuthSessionExpiry { copt, .. }
            | GroupAccountPolicyOpt::PasswordMinimumLength { copt, .. }
            | GroupAccountPolicyOpt::PrivilegedSessionExpiry { copt, .. } => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            GroupAccountPolicyOpt::Enable { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client.group_account_policy_enable(name).await {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Group enabled for account policy.");
                }
            }
            GroupAccountPolicyOpt::AuthSessionExpiry { name, expiry, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_authsession_expiry_set(name, *expiry)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated authsession expiry.");
                }
            }
            GroupAccountPolicyOpt::PasswordMinimumLength { name, length, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_password_minimum_length_set(name, *length)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated password minimum length.");
                }
            }
            GroupAccountPolicyOpt::PrivilegedSessionExpiry { name, expiry, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_privilege_expiry_set(name, *expiry)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated authsession expiry.");
                }
            }
        }
    }
}
