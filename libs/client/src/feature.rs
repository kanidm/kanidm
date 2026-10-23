use crate::{ClientError, KanidmClient};
use kanidm_proto::scim_v1::{
    client::{
        // ScimEntryFeature,
        ScimListFeature,
    },
    ScimEntryGetQuery,
};
// use uuid::Uuid;

impl KanidmClient {
    pub async fn idm_feature_list(
        &self,
        query: Option<ScimEntryGetQuery>,
    ) -> Result<ScimListFeature, ClientError> {
        self.perform_get_request_query("/scim/v1/Feature", query)
            .await
    }

    pub async fn idm_feature_enable<P: AsRef<str> + std::fmt::Display>(
        &self,
        account_id: P,
    ) -> Result<(), ClientError> {
        // let account_id = account_id.as_ref();
        self.perform_post_request(&format!("/scim/v1/Feature/{account_id}/_enable"), true)
            .await
    }

    pub async fn idm_feature_disable<P: AsRef<str> + std::fmt::Display>(
        &self,
        account_id: P,
    ) -> Result<(), ClientError> {
        // let account_id = account_id.as_ref();
        self.perform_post_request(&format!("/scim/v1/Feature/{account_id}/_enable"), false)
            .await
    }
}
