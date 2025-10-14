use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{
    client::{ScimEntryMessage, ScimListMessage},
    ScimEntryGetQuery,
};
use uuid::Uuid;

impl KanidmClient {
    pub async fn idm_message_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimListMessage, ClientError> {
        self.perform_get_request_query("/scim/v1/Message", query)
            .await
    }

    /// Queue a test message to be sent to a person.
    pub async fn idm_message_send_test(&self, to: &str) -> Result<(), ClientError> {
        self.perform_get_request(&format!("/scim/v1/Person/{to}/_message/_send_test"))
            .await
    }

    pub async fn idm_message_list_ready(&self) -> Result<ScimListMessage, ClientError> {
        self.perform_get_request("/scim/v1/Message/_ready").await
    }

    pub async fn idm_message_get(&self, message_id: Uuid) -> Result<ScimEntryMessage, ClientError> {
        self.perform_get_request(&format!("/scim/v1/Message/{message_id}"))
            .await
    }

    pub async fn idm_message_mark_sent(&self, message_id: Uuid) -> Result<(), ClientError> {
        self.perform_post_request(&format!("/scim/v1/Message/{message_id}/_sent"), ())
            .await
    }
}
