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
}
