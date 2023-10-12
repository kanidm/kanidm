use crate::{ClientError, KanidmClient};

impl KanidmClient {
    pub async fn system_password_badlist_get(&self) -> Result<Vec<String>, ClientError> {
        let list: Option<Vec<String>> = self
            .perform_get_request("/v1/system/_attr/badlist_password")
            .await?;
        Ok(list.unwrap_or_default())
    }

    pub async fn system_password_badlist_append(
        &self,
        list: Vec<String>,
    ) -> Result<(), ClientError> {
        self.perform_post_request("/v1/system/_attr/badlist_password", list)
            .await
    }

    pub async fn system_password_badlist_remove(
        &self,
        list: Vec<String>,
    ) -> Result<(), ClientError> {
        self.perform_delete_request_with_body("/v1/system/_attr/badlist_password", list)
            .await
    }

    pub async fn system_denied_names_get(&self) -> Result<Vec<String>, ClientError> {
        let list: Option<Vec<String>> = self
            .perform_get_request("/v1/system/_attr/denied_name")
            .await?;
        Ok(list.unwrap_or_default())
    }

    pub async fn system_denied_names_append(&self, list: &Vec<String>) -> Result<(), ClientError> {
        self.perform_post_request("/v1/system/_attr/denied_name", list)
            .await
    }

    pub async fn system_denied_names_remove(&self, list: &Vec<String>) -> Result<(), ClientError> {
        self.perform_delete_request_with_body("/v1/system/_attr/denied_name", list)
            .await
    }

    pub async fn system_authsession_expiry_get(&self) -> Result<u32, ClientError> {
        let list: Option<[String; 1]> = self
            .perform_get_request("/v1/system/_attr/authsession_expiry")
            .await?;
        list.ok_or(ClientError::EmptyResponse).and_then(|s| {
            s[0].parse::<u32>()
                .map_err(|err| ClientError::InvalidResponseFormat(err.to_string()))
        })
    }

    pub async fn system_authsession_expiry_set(&self, expiry: u32) -> Result<(), ClientError> {
        self.perform_put_request(
            "/v1/system/_attr/authsession_expiry",
            vec![expiry.to_string()],
        )
        .await
    }

    pub async fn system_auth_privilege_expiry_get(&self) -> Result<u32, ClientError> {
        let list: Option<[String; 1]> = self
            .perform_get_request("/v1/system/_attr/privilege_expiry")
            .await?;
        list.ok_or(ClientError::EmptyResponse).and_then(|s| {
            s[0].parse::<u32>()
                .map_err(|err| ClientError::InvalidResponseFormat(err.to_string()))
        })
    }

    pub async fn system_auth_privilege_expiry_set(&self, expiry: u32) -> Result<(), ClientError> {
        self.perform_put_request(
            "/v1/system/_attr/privilege_expiry",
            vec![expiry.to_string()],
        )
        .await
    }
}
