use crate::ClientError;
use crate::KanidmClient;
use kanidm_proto::v1::Entry;

impl KanidmClient {
    /*
    pub async fn idm_service_account_get_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/service_account/{}/_ssh_pubkeys/{}", id, tag).as_str())
            .await
    }

    pub async fn idm_service_account_get_ssh_pubkeys(&self, id: &str) -> Result<Vec<String>, ClientError> {
        self.perform_get_request(format!("/v1/service_account/{}/_ssh_pubkeys", id).as_str())
            .await
    }
    */

    pub async fn idm_service_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/service_account").await
    }

    pub async fn idm_service_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/service_account/{}", id).as_str())
            .await
    }

    pub async fn idm_service_account_post_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
        pubkey: &str,
    ) -> Result<(), ClientError> {
        let sk = (tag.to_string(), pubkey.to_string());
        self.perform_post_request(
            format!("/v1/service_account/{}/_ssh_pubkeys", id).as_str(),
            sk,
        )
        .await
    }

    pub async fn idm_service_account_delete_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(
            format!("/v1/service_account/{}/_ssh_pubkeys/{}", id, tag).as_str(),
        )
        .await
    }
}
