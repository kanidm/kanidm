use crate::common::OpType;
use crate::{handle_client_error, GroupAccountPolicyOpt};

impl GroupAccountPolicyOpt {
    pub fn debug(&self) -> bool {
        match self {
            GroupAccountPolicyOpt::Enable { copt, .. }
            | GroupAccountPolicyOpt::AuthSessionExpiry { copt, .. }
            | GroupAccountPolicyOpt::CredentialTypeMinimum { copt, .. }
            | GroupAccountPolicyOpt::PasswordMinimumLength { copt, .. }
            | GroupAccountPolicyOpt::WebauthnAttestationCaList { copt, .. }
            | GroupAccountPolicyOpt::LimitSearchMaxResults { copt, .. }
            | GroupAccountPolicyOpt::LimitSearchMaxFilterTest { copt, .. }
            | GroupAccountPolicyOpt::AllowPrimaryCredFallback { copt, .. }
            | GroupAccountPolicyOpt::ResetWebauthnAttestationCaList { copt, .. }
            | GroupAccountPolicyOpt::ResetAuthSessionExpiry { copt, .. }
            | GroupAccountPolicyOpt::ResetPasswordMinimumLength { copt, .. }
            | GroupAccountPolicyOpt::ResetPrivilegedSessionExpiry { copt, .. }
            | GroupAccountPolicyOpt::ResetLimitSearchMaxResults { copt, .. }
            | GroupAccountPolicyOpt::ResetLimitSearchMaxFilterTest { copt, .. }
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

            GroupAccountPolicyOpt::ResetAuthSessionExpiry { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_authsession_expiry_reset(name)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Successfully reset authsession expiry.");
                }
            }

            GroupAccountPolicyOpt::CredentialTypeMinimum { name, value, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_credential_type_minimum_set(name, value.as_str())
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated credential type minimum.");
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
            GroupAccountPolicyOpt::ResetPasswordMinimumLength { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_password_minimum_length_reset(name)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Successfully reset password minimum length.");
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
                    println!("Updated privilege session expiry.");
                }
            }
            GroupAccountPolicyOpt::ResetPrivilegedSessionExpiry { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_privilege_expiry_reset(name)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Successfully reset privilege session expiry.");
                }
            }
            GroupAccountPolicyOpt::WebauthnAttestationCaList {
                name,
                attestation_ca_list_json,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_webauthn_attestation_set(name, attestation_ca_list_json)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated webauthn attestation CA list.");
                }
            }

            GroupAccountPolicyOpt::ResetWebauthnAttestationCaList { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_webauthn_attestation_reset(name)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Successfully reset webauthn attestation CA list.");
                }
            }

            GroupAccountPolicyOpt::LimitSearchMaxResults {
                name,
                maximum,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_results(name, *maximum)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated search maximum results limit.");
                }
            }
            GroupAccountPolicyOpt::ResetLimitSearchMaxResults { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_results_reset(name)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Successfully reset search maximum results limit to default.");
                }
            }
            GroupAccountPolicyOpt::LimitSearchMaxFilterTest {
                name,
                maximum,
                copt,
            } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_filter_test(name, *maximum)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated search maximum filter test limit.");
                }
            }
            GroupAccountPolicyOpt::ResetLimitSearchMaxFilterTest { name, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_filter_test_reset(name)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Successfully reset search maximum filter test limit.");
                }
            }
            GroupAccountPolicyOpt::AllowPrimaryCredFallback { name, allow, copt } => {
                let client = copt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_allow_primary_cred_fallback(name, *allow)
                    .await
                {
                    handle_client_error(e, copt.output_mode);
                } else {
                    println!("Updated primary credential fallback policy.");
                }
            }
        }
    }
}
