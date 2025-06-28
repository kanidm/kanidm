use crate::{ClientError, KanidmClient};
use kanidm_proto::v1::Entry;

impl KanidmClient {
    pub async fn idm_group_search(&self, id: &str) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request(&format!("/v1/group/_search/{id}"))
            .await
    }

    pub async fn idm_group_purge_attr(&self, id: &str, attr: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/group/{id}/_attr/{attr}").as_str())
            .await
    }

    pub async fn group_account_policy_enable(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            &format!("/v1/group/{id}/_attr/class"),
            vec!["account_policy".to_string()],
        )
        .await
    }

    pub async fn group_rename(&self, name: &str, new_name: &str) -> Result<(), ClientError> {
        self.perform_put_request(&format!("/v1/group/{name}/_attr/name"), vec![new_name])
            .await
    }

    pub async fn group_account_policy_authsession_expiry_set(
        &self,
        id: &str,
        expiry: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/authsession_expiry"),
            vec![expiry.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_authsession_expiry_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_attr/authsession_expiry"))
            .await
    }

    pub async fn group_account_policy_credential_type_minimum_set(
        &self,
        id: &str,
        value: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/credential_type_minimum"),
            vec![value.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_password_minimum_length_set(
        &self,
        id: &str,
        length: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/auth_password_minimum_length"),
            vec![length.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_password_minimum_length_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!(
            "/v1/group/{id}/_attr/auth_password_minimum_length"
        ))
        .await
    }

    pub async fn group_account_policy_privilege_expiry_set(
        &self,
        id: &str,
        expiry: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/privilege_expiry"),
            vec![expiry.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_privilege_expiry_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_attr/privilege_expiry"))
            .await
    }

    pub async fn group_account_policy_webauthn_attestation_set(
        &self,
        id: &str,
        att_ca_list: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/webauthn_attestation_ca_list"),
            vec![att_ca_list.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_webauthn_attestation_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!(
            "/v1/group/{id}/_attr/webauthn_attestation_ca_list"
        ))
        .await
    }

    pub async fn group_account_policy_limit_search_max_results(
        &self,
        id: &str,
        maximum: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/limit_search_max_results"),
            vec![maximum.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_limit_search_max_results_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{id}/_attr/limit_search_max_results"))
            .await
    }

    pub async fn group_account_policy_limit_search_max_filter_test(
        &self,
        id: &str,
        maximum: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/limit_search_max_filter_test"),
            vec![maximum.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_limit_search_max_filter_test_reset(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!(
            "/v1/group/{id}/_attr/limit_search_max_filter_test"
        ))
        .await
    }

    pub async fn group_account_policy_allow_primary_cred_fallback(
        &self,
        id: &str,
        allow: bool,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{id}/_attr/allow_primary_cred_fallback"),
            vec![allow.to_string()],
        )
        .await
    }

    pub async fn idm_group_purge_mail(&self, id: &str) -> Result<(), ClientError> {
        self.idm_group_purge_attr(id, "mail").await
    }

    pub async fn idm_group_set_mail<T: serde::Serialize>(
        &self,
        id: &str,
        values: &[T],
    ) -> Result<(), ClientError> {
        self.perform_put_request(&format!("/v1/group/{id}/_attr/mail"), values)
            .await
    }

    pub async fn idm_group_get_mail(&self, id: &str) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(&format!("/v1/group/{id}/_attr/mail"))
            .await
    }

    pub async fn idm_group_purge_description(&self, id: &str) -> Result<(), ClientError> {
        self.idm_group_purge_attr(id, "description").await
    }

    pub async fn idm_group_set_description(
        &self,
        id: &str,
        description: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(&format!("/v1/group/{id}/_attr/description"), &[description])
            .await
    }
}
