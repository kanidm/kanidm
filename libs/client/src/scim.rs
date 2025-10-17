use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{ScimEntryGeneric, ScimEntryGetQuery, ScimSyncRequest, ScimSyncState, client::{ScimListEntry, ScimEntryPostGeneric, ScimEntryPutGeneric} };

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

    /// Retrieve a Generic SCIM Entry as a JSON Value. This can retrieve any
    /// type of entry that Kanidm supports.
    pub async fn scim_v1_entry_get(
        &self,
        name_or_uuid: &str,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimEntryGeneric, ClientError> {
        self.perform_get_request_query(format!("/scim/v1/Entry/{name_or_uuid}").as_str(), query)
            .await
    }

    /// Retrieve a Person as a SCIM JSON Value.
    pub async fn scim_v1_person_get(
        &self,
        name_or_uuid: &str,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimEntryGeneric, ClientError> {
        self.perform_get_request_query(format!("/scim/v1/Person/{name_or_uuid}").as_str(), query)
            .await
    }

    pub async fn scim_v1_entry_query(
        &self,
        query: ScimEntryGetQuery,
    ) -> Result<ScimListEntry, ClientError> {
        self.perform_get_request_query(format!("/scim/v1/Entry").as_str(), Some(query))
            .await
    }

    pub async fn scim_v1_entry_create(
        &self,
        entry: ScimEntryPostGeneric,
    ) -> Result<ScimEntryGeneric, ClientError> {
        self.perform_post_request(format!("/scim/v1/Entry").as_str(), entry)
            .await
    }

    pub async fn scim_v1_entry_update(
        &self,
        entry: ScimEntryPutGeneric,
    ) -> Result<ScimEntryGeneric, ClientError> {
        self.perform_put_request(format!("/scim/v1/Entry").as_str(), entry)
            .await
    }

    pub async fn scim_v1_entry_delete(
        &self,
        id: &str
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/scim/v1/Entry/{id}").as_str())
            .await
    }
}
