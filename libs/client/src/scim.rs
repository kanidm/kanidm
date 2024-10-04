use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{ScimEntryGeneric, ScimEntryGetQuery, ScimSyncRequest, ScimSyncState};

impl KanidmClient {
    // TODO: testing for this
    pub async fn scim_v1_sync_status(&self) -> Result<ScimSyncState, ClientError> {
        self.perform_get_request("/scim/v1/Sync").await
    }

    // TODO: testing for this
    pub async fn scim_v1_sync_update(
        &self,
        scim_sync_request: &ScimSyncRequest,
    ) -> Result<(), ClientError> {
        self.perform_post_request("/scim/v1/Sync", scim_sync_request)
            .await
    }

    /// Retrieve a Generic SCIM Entry as a JSON Value. This can retrieve any
    /// type of entry that Kanidm supports.
    pub async fn scim_v1_entry_get(
        &self,
        name_or_uuid: &str,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimEntryGeneric, ClientError> {
        self.perform_get_request_query(format!("/scim/v1/Entry/{}", name_or_uuid).as_str(), query)
            .await
    }

    /// Retrieve a Person as a SCIM JSON Value.
    pub async fn scim_v1_person_get(
        &self,
        name_or_uuid: &str,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimEntryGeneric, ClientError> {
        self.perform_get_request_query(format!("/scim/v1/Person/{}", name_or_uuid).as_str(), query)
            .await
    }
}
