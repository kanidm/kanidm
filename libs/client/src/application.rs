use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::client::{ScimEntryApplication, ScimEntryApplicationPost};

impl KanidmClient {
    /// Delete an application
    pub async fn idm_application_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/scim/v1/Application/{}", id).as_str())
            .await
    }

    /// Create an application
    pub async fn idm_application_create(
        &self,
        application: &ScimEntryApplicationPost,
    ) -> Result<ScimEntryApplication, ClientError> {
        self.perform_post_request("/scim/v1/Application", application)
            .await
    }
}
