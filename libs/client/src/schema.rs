use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{
    client::{ScimListSchemaAttribute, ScimListSchemaClass},
    ScimEntryGetQuery,
};

impl KanidmClient {
    pub async fn scim_schema_class_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimListSchemaClass, ClientError> {
        self.perform_get_request_query("/scim/v1/Class", query)
            .await
    }

    pub async fn scim_schema_attribute_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimListSchemaAttribute, ClientError> {
        self.perform_get_request_query("/scim/v1/Attribute", query)
            .await
    }
}
