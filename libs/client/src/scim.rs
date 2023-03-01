use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{ScimSyncRequest, ScimSyncState};

impl KanidmClient {
    pub async fn scim_v1_sync_status(&self) -> Result<ScimSyncState, ClientError> {
        self.perform_get_request("/scim/v1/Sync").await
    }

    pub async fn scim_v1_sync_update(
        &self,
        scim_sync_request: &ScimSyncRequest,
    ) -> Result<(), ClientError> {
        self.perform_post_request("/scim/v1/Sync", scim_sync_request)
            .await
    }
}
