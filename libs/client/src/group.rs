use crate::{ClientError, KanidmClient};

impl KanidmClient {
    pub async fn group_account_policy_enable(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            &format!("/v1/group/{}/_attr/class", id),
            vec!["account_policy".to_string()],
        )
        .await
    }

    pub async fn group_account_policy_authsession_expiry_set(
        &self,
        id: &str,
        expiry: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{}/_attr/authsession_expiry", id),
            vec![expiry.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_credential_type_minimum_set(
        &self,
        id: &str,
        value: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{}/_attr/credential_type_minimum", id),
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
            &format!("/v1/group/{}/_attr/auth_password_minimum_length", id),
            vec![length.to_string()],
        )
        .await
    }

    pub async fn group_account_policy_privilege_expiry_set(
        &self,
        id: &str,
        expiry: u32,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("/v1/group/{}/_attr/privilege_expiry", id),
            vec![expiry.to_string()],
        )
        .await
    }
}
