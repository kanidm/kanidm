use crate::ClientError;
use crate::KanidmClient;
use kanidm_proto::v1::AccountUnixExtend;
use kanidm_proto::v1::CredentialStatus;
use kanidm_proto::v1::Entry;
use std::collections::BTreeMap;

impl KanidmClient {
    pub async fn idm_service_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/service_account").await
    }

    pub async fn idm_service_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/service_account/{}", id).as_str())
            .await
    }

    pub async fn idm_service_account_create(
        &self,
        name: &str,
        displayname: &str,
    ) -> Result<(), ClientError> {
        let mut new_acct = Entry {
            attrs: BTreeMap::new(),
        };
        new_acct
            .attrs
            .insert("name".to_string(), vec![name.to_string()]);
        new_acct
            .attrs
            .insert("displayname".to_string(), vec![displayname.to_string()]);
        self.perform_post_request("/v1/service_account", new_acct)
            .await
    }

    pub async fn idm_service_account_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/service_account/", id].concat().as_str())
            .await
    }

    pub async fn idm_service_account_add_attr(
        &self,
        id: &str,
        attr: &str,
        values: &[&str],
    ) -> Result<(), ClientError> {
        let msg: Vec<_> = values.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(
            format!("/v1/service_account/{}/_attr/{}", id, attr).as_str(),
            msg,
        )
        .await
    }

    pub async fn idm_service_account_set_attr(
        &self,
        id: &str,
        attr: &str,
        values: &[&str],
    ) -> Result<(), ClientError> {
        let m: Vec<_> = values.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(
            format!("/v1/service_account/{}/_attr/{}", id, attr).as_str(),
            m,
        )
        .await
    }

    pub async fn idm_service_account_get_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(format!("/v1/service_account/{}/_attr/{}", id, attr).as_str())
            .await
    }

    pub async fn idm_service_account_purge_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/service_account/{}/_attr/{}", id, attr).as_str())
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

    pub async fn idm_service_account_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
        shell: Option<&str>,
    ) -> Result<(), ClientError> {
        let ux = AccountUnixExtend {
            shell: shell.map(str::to_string),
            gidnumber,
        };
        self.perform_post_request(format!("/v1/service_account/{}/_unix", id).as_str(), ux)
            .await
    }

    pub async fn idm_service_account_into_person(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/service_account/{}/_into_person", id).as_str(),
            (),
        )
        .await
    }

    pub async fn idm_service_account_get_credential_status(
        &self,
        id: &str,
    ) -> Result<CredentialStatus, ClientError> {
        let res: Result<CredentialStatus, ClientError> = self
            .perform_get_request(format!("/v1/service_account/{}/_credential/_status", id).as_str())
            .await;
        res.and_then(|cs| {
            if cs.creds.is_empty() {
                Err(ClientError::EmptyResponse)
            } else {
                Ok(cs)
            }
        })
    }

    pub async fn idm_service_account_generate_password(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        let res: Result<String, ClientError> = self
            .perform_get_request(
                format!("/v1/service_account/{}/_credential/_generate", id).as_str(),
            )
            .await;
        res.and_then(|pw| {
            if pw.is_empty() {
                Err(ClientError::EmptyResponse)
            } else {
                Ok(pw)
            }
        })
    }
}
