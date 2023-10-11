use crate::{ClientError, KanidmClient};
use kanidm_proto::constants::{ATTR_DESCRIPTION, ATTR_NAME};
use kanidm_proto::v1::Entry;
use std::collections::BTreeMap;
use url::Url;

impl KanidmClient {
    pub async fn idm_sync_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/sync_account").await
    }

    pub async fn idm_sync_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/sync_account/{}", id).as_str())
            .await
    }

    pub async fn idm_sync_account_set_credential_portal(
        &self,
        id: &str,
        url: Option<&Url>,
    ) -> Result<(), ClientError> {
        let m = if let Some(url) = url {
            vec![url.to_owned()]
        } else {
            vec![]
        };

        self.perform_put_request(
            format!("/v1/sync_account/{}/_attr/sync_credential_portal", id).as_str(),
            m,
        )
        .await
    }

    pub async fn idm_sync_account_get_credential_portal(
        &self,
        id: &str,
    ) -> Result<Option<Url>, ClientError> {
        self.perform_get_request(
            format!("/v1/sync_account/{}/_attr/sync_credential_portal", id).as_str(),
        )
        .await
        .map(|values: Vec<Url>| values.get(0).cloned())
    }

    pub async fn idm_sync_account_set_yield_attributes(
        &self,
        id: &str,
        attrs: &Vec<String>,
    ) -> Result<(), ClientError> {
        // let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(
            format!("/v1/sync_account/{}/_attr/sync_yield_authority", id).as_str(),
            &attrs,
        )
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
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        if let Some(description) = description {
            new_acct
                .attrs
                .insert(ATTR_DESCRIPTION.to_string(), vec![description.to_string()]);
        }

        self.perform_post_request("/v1/sync_account", new_acct)
            .await
    }

    /// Creates a sync token for a given sync account
    pub async fn idm_sync_account_generate_token(
        &self,
        id: &str,
        label: &str,
    ) -> Result<String, ClientError> {
        self.perform_post_request(
            format!("/v1/sync_account/{}/_sync_token", id).as_str(),
            label,
        )
        .await
    }

    pub async fn idm_sync_account_destroy_token(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/sync_account/{}/_sync_token", id,).as_str())
            .await
    }

    pub async fn idm_sync_account_force_refresh(&self, id: &str) -> Result<(), ClientError> {
        let mut update_entry = Entry {
            attrs: BTreeMap::new(),
        };

        update_entry
            .attrs
            .insert("sync_cookie".to_string(), Vec::with_capacity(0));

        self.perform_patch_request(format!("/v1/sync_account/{}", id).as_str(), update_entry)
            .await
    }

    pub async fn idm_sync_account_finalise(&self, id: &str) -> Result<(), ClientError> {
        self.perform_get_request(format!("/v1/sync_account/{}/_finalise", id).as_str())
            .await
    }

    pub async fn idm_sync_account_terminate(&self, id: &str) -> Result<(), ClientError> {
        self.perform_get_request(format!("/v1/sync_account/{}/_terminate", id).as_str())
            .await
    }
}
