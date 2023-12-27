use crate::{ClientError, KanidmClient};
use kanidm_proto::constants::ATTR_NAME;
use kanidm_proto::v1::Entry;
use std::collections::BTreeMap;

impl KanidmClient {
    pub async fn idm_application_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/application").await
    }

    pub async fn idm_application_create(&self, name: &str) -> Result<(), ClientError> {
        let mut new_app = Entry {
            attrs: BTreeMap::new(),
        };
        new_app
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        self.perform_post_request("/v1/application", new_app).await
    }

    pub async fn idm_application_delete(&self, name: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/application/", name].concat().as_str())
            .await
    }

    pub async fn idm_application_add_members(
        &self,
        id: &str,
        members: &[&str],
    ) -> Result<(), ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(&format!("/v1/application/{}/_attr/member", id), m)
            .await
    }
}
