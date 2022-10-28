use crate::{ClientError, KanidmClient};
use kanidm_proto::v1::Entry;
use std::collections::BTreeMap;

impl KanidmClient {
    pub async fn idm_sync_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/sync_account").await
    }

    pub async fn idm_sync_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/sync_account/{}", id).as_str())
            .await
    }

    pub async fn idm_sync_account_create(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), ClientError> {
        let mut new_acct = Entry {
            attrs: BTreeMap::new(),
        };
        new_acct
            .attrs
            .insert("name".to_string(), vec![name.to_string()]);
        if let Some(description) = description {
            new_acct
                .attrs
                .insert("description".to_string(), vec![description.to_string()]);
        }
        self.perform_post_request("/v1/sync_account", new_acct)
            .await
    }
}
