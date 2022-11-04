use crate::{ClientError, KanidmClient};

impl KanidmClient {
    pub async fn scim_v1_sync_status(&self) -> Result<(), ClientError> {
        self.perform_get_request("/scim/v1/Sync").await
    }

    // pub async fn scim_v1_sync_
}
