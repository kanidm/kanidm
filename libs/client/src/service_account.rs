use std::collections::BTreeMap;

use kanidm_proto::constants::{ATTR_DISPLAYNAME, ATTR_ENTRY_MANAGED_BY, ATTR_MAIL, ATTR_NAME};
use kanidm_proto::v1::{AccountUnixExtend, ApiToken, ApiTokenGenerate, CredentialStatus, Entry};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ClientError, KanidmClient};

impl KanidmClient {
    pub async fn idm_service_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/service_account").await
    }

    pub async fn idm_service_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/service_account/{}", id).as_str())
            .await
    }

    /// Handles creating a service account
    pub async fn idm_service_account_create(
        &self,
        name: &str,
        displayname: &str,
        entry_managed_by: &str,
    ) -> Result<(), ClientError> {
        let mut new_acct = Entry {
            attrs: BTreeMap::new(),
        };
        new_acct
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        new_acct
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_acct.attrs.insert(
            ATTR_ENTRY_MANAGED_BY.to_string(),
            vec![entry_managed_by.to_string()],
        );

        self.perform_post_request("/v1/service_account", new_acct)
            .await
    }

    pub async fn idm_service_account_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/service_account/", id].concat().as_str())
            .await
    }

    pub async fn idm_service_account_update(
        &self,
        id: &str,
        newname: Option<&str>,
        displayname: Option<&str>,
        entry_managed_by: Option<&str>,
        mail: Option<&[String]>,
    ) -> Result<(), ClientError> {
        let mut update_entry = Entry {
            attrs: BTreeMap::new(),
        };

        if let Some(newname) = newname {
            update_entry
                .attrs
                .insert(ATTR_NAME.to_string(), vec![newname.to_string()]);
        }

        if let Some(newdisplayname) = displayname {
            update_entry.attrs.insert(
                ATTR_DISPLAYNAME.to_string(),
                vec![newdisplayname.to_string()],
            );
        }

        if let Some(entry_managed_by) = entry_managed_by {
            update_entry.attrs.insert(
                ATTR_ENTRY_MANAGED_BY.to_string(),
                vec![entry_managed_by.to_string()],
            );
        }

        if let Some(mail) = mail {
            update_entry
                .attrs
                .insert(ATTR_MAIL.to_string(), mail.to_vec());
        }

        self.perform_patch_request(format!("/v1/service_account/{}", id).as_str(), update_entry)
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
        // The username or uuid of the account
        id: &str,
        // The GID number to set for the account
        gidnumber: Option<u32>,
        // Set a default login shell
        shell: Option<&str>,
    ) -> Result<(), ClientError> {
        let ux = AccountUnixExtend {
            shell: shell.map(str::to_string),
            gidnumber,
        };
        self.perform_post_request(format!("/v1/service_account/{}/_unix", id).as_str(), ux)
            .await
    }

    // TODO: test coverage for this, but there's a weird issue with ACPs on apply
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

    pub async fn idm_service_account_list_api_token(
        &self,
        id: &str,
    ) -> Result<Vec<ApiToken>, ClientError> {
        // This ends up at [kanidmd_core::actors::v1_write::QueryServerWriteV1::handle_service_account_api_token_generate]
        self.perform_get_request(format!("/v1/service_account/{}/_api_token", id).as_str())
            .await
    }

    pub async fn idm_service_account_generate_api_token(
        &self,
        id: &str,
        label: &str,
        expiry: Option<OffsetDateTime>,
        read_write: bool,
    ) -> Result<String, ClientError> {
        let new_token = ApiTokenGenerate {
            label: label.to_string(),
            expiry,
            read_write,
        };
        self.perform_post_request(
            format!("/v1/service_account/{}/_api_token", id).as_str(),
            new_token,
        )
        .await
    }

    pub async fn idm_service_account_destroy_api_token(
        &self,
        id: &str,
        token_id: Uuid,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(
            format!(
                "/v1/service_account/{}/_api_token/{}",
                id,
                &token_id.to_string()
            )
            .as_str(),
        )
        .await
    }
}
