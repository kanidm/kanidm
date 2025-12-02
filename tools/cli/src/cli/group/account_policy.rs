use crate::OpType;
use crate::{
    handle_client_error, handle_group_account_policy_error, GroupAccountPolicyOpt,
    KanidmClientParser,
};

impl GroupAccountPolicyOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            GroupAccountPolicyOpt::Enable { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.group_account_policy_enable(name).await {
                    handle_client_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Group enabled for account policy.");
                }
            }
            GroupAccountPolicyOpt::AuthSessionExpiry { name, expiry } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_authsession_expiry_set(name, *expiry)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode.print_message("Updated authsession expiry.");
                }
            }

            GroupAccountPolicyOpt::ResetAuthSessionExpiry { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_authsession_expiry_reset(name)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Successfully reset authsession expiry.");
                }
            }

            GroupAccountPolicyOpt::CredentialTypeMinimum { name, value } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_credential_type_minimum_set(name, value.as_str())
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated credential type minimum.");
                }
            }
            GroupAccountPolicyOpt::PasswordMinimumLength { name, length } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_password_minimum_length_set(name, *length)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated password minimum length.");
                }
            }
            GroupAccountPolicyOpt::ResetPasswordMinimumLength { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_password_minimum_length_reset(name)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Successfully reset password minimum length.");
                }
            }
            GroupAccountPolicyOpt::PrivilegedSessionExpiry { name, expiry } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_privilege_expiry_set(name, *expiry)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated privilege session expiry.");
                }
            }
            GroupAccountPolicyOpt::ResetPrivilegedSessionExpiry { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_privilege_expiry_reset(name)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Successfully reset privilege session expiry.");
                }
            }
            GroupAccountPolicyOpt::WebauthnAttestationCaList {
                name,
                attestation_ca_list_json_file,
            } => {
                let client = opt.to_client(OpType::Write).await;
                let json = std::fs::read_to_string(attestation_ca_list_json_file).unwrap_or_else(|e| {
                    error!("Could not read attestation CA list JSON file {attestation_ca_list_json_file:?}: {e:?}");
                    std::process::exit(1);
                });

                if let Err(e) = client
                    .group_account_policy_webauthn_attestation_set(name, &json)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated webauthn attestation CA list.");
                }
            }

            GroupAccountPolicyOpt::ResetWebauthnAttestationCaList { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_webauthn_attestation_reset(name)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Successfully reset webauthn attestation CA list.");
                }
            }

            GroupAccountPolicyOpt::LimitSearchMaxResults { name, maximum } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_results(name, *maximum)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated search maximum results limit.");
                }
            }
            GroupAccountPolicyOpt::ResetLimitSearchMaxResults { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_results_reset(name)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode.print_message(
                        "Successfully reset search maximum results limit to default.",
                    );
                }
            }
            GroupAccountPolicyOpt::LimitSearchMaxFilterTest { name, maximum } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_filter_test(name, *maximum)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated search maximum filter test limit.");
                }
            }
            GroupAccountPolicyOpt::ResetLimitSearchMaxFilterTest { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_limit_search_max_filter_test_reset(name)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Successfully reset search maximum filter test limit.");
                }
            }
            GroupAccountPolicyOpt::AllowPrimaryCredFallback { name, allow } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .group_account_policy_allow_primary_cred_fallback(name, *allow)
                    .await
                {
                    handle_group_account_policy_error(e, opt.output_mode);
                } else {
                    opt.output_mode
                        .print_message("Updated primary credential fallback policy.");
                }
            }
        }
    }
}
