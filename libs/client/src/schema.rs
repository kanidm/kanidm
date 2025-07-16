use crate::{KanidmClient, ClientError};
use kanidm_proto::scim_v1::{
    client::{ScimListSchemaClass, ScimListSchemaAttribute},
    ScimEntryGetQuery,
};

impl KanidmClient {
    pub async fn scim_schema_class_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result< ScimListSchemaClass , ClientError> {
        self.perform_get_request_query("/scim/v1/Class", query)
            .await
    }

    pub async fn scim_schema_attribute_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result< ScimListSchemaAttribute , ClientError> {
        self.perform_get_request_query("/scim/v1/Attribute", query)
            .await
    }
}
