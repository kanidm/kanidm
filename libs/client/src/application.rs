use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{
    client::{ScimEntryApplication, ScimEntryApplicationPost, ScimListApplication,
    ScimApplicationPasswordCreate, ScimApplicationPassword},
    ScimEntryGetQuery,
};

impl KanidmClient {
    /// Delete an application
    pub async fn idm_application_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/scim/v1/Application/{id}").as_str())
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

    pub async fn idm_application_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimListApplication, ClientError> {
        self.perform_get_request_query("/scim/v1/Application", query)
            .await
    }

    pub async fn idm_application_get(
        &self,
        name_or_uuid: &str,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimEntryApplication, ClientError> {
        self.perform_get_request_query(
            format!("/scim/v1/Application/{name_or_uuid}").as_str(),
            query,
        )
        .await
    }

    /*
    pub async fn idm_person_application_list(
        &self,
        name_or_uuid: &str,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<Vec<()>, ClientError> {
        self.perform_get_request(
            format!("/scim/v1/Person/{}/Application", name_or_uuid).as_str(),
            query
        )
            .await
    }
    */

    pub async fn idm_application_password_create(
        &self,
        name_or_uuid: &str,
        request: &ScimApplicationPasswordCreate,
    ) -> Result<ScimApplicationPassword, ClientError> {
        self.perform_post_request(
            format!("/scim/v1/Person/{}/Application/_create_password", name_or_uuid).as_str()
        , request)
            .await
    }
}
