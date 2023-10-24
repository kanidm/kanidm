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
}
