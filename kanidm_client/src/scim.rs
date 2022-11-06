use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::ScimSyncState;

impl KanidmClient {
    pub async fn scim_v1_sync_status(&self) -> Result<ScimSyncState, ClientError> {
        self.perform_get_request("/scim/v1/Sync").await
    }

    // pub async fn scim_v1_sync_
}
