
use crate::KanidmClient;
use crate::ClientError;
use kanidm_proto::v1::Entry;
use std::collections::BTreeMap;

impl KanidmClient {
    pub async fn idm_person_account_create(&self, name: &str, displayname: &str) -> Result<(), ClientError> {
        let mut new_acct = Entry {
            attrs: BTreeMap::new(),
        };
        new_acct
            .attrs
            .insert("name".to_string(), vec![name.to_string()]);
        new_acct
            .attrs
            .insert("displayname".to_string(), vec![displayname.to_string()]);
        self.perform_post_request("/v1/person", new_acct).await
    }

    pub async fn idm_person_account_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/person/", id].concat().as_str())
            .await
    }

    pub async fn idm_person_account_add_attr(
        &self,
        id: &str,
        attr: &str,
        values: &[&str],
    ) -> Result<(), ClientError> {
        let msg: Vec<_> = values.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(format!("/v1/person/{}/_attr/{}", id, attr).as_str(), msg)
            .await
    }

    pub async fn idm_person_account_set_attr(
        &self,
        id: &str,
        attr: &str,
        values: &[&str],
    ) -> Result<(), ClientError> {
        let m: Vec<_> = values.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(format!("/v1/person/{}/_attr/{}", id, attr).as_str(), m)
            .await
    }

    pub async fn idm_person_account_get_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(format!("/v1/person/{}/_attr/{}", id, attr).as_str())
            .await
    }

    pub async fn idm_person_account_purge_attr(&self, id: &str, attr: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/person/{}/_attr/{}", id, attr).as_str())
            .await
    }

}

