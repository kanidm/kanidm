use std::collections::BTreeMap;

use kanidm_proto::v1::{AccountUnixExtend, CredentialStatus, Entry, SingleStringRequest};

use crate::{ClientError, KanidmClient};

impl KanidmClient {
    pub async fn idm_person_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/person").await
    }

    pub async fn idm_person_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/person/{}", id).as_str())
            .await
    }

    pub async fn idm_person_account_create(
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
        self.perform_post_request("/v1/person", new_acct).await
    }

    pub async fn idm_person_account_update(
        &self,
        id: &str,
        newname: Option<&str>,
        displayname: Option<&str>,
        legalname: Option<&str>,
        mail: Option<&[String]>,
    ) -> Result<(), ClientError> {
        let mut update_entry = Entry {
            attrs: BTreeMap::new(),
        };

        if let Some(newname) = newname {
            update_entry
                .attrs
                .insert("name".to_string(), vec![newname.to_string()]);
        }
        if let Some(newdisplayname) = displayname {
            update_entry
                .attrs
                .insert("displayname".to_string(), vec![newdisplayname.to_string()]);
        }
        if let Some(newlegalname) = legalname {
            update_entry
                .attrs
                .insert("legalname".to_string(), vec![newlegalname.to_string()]);
        }
        if let Some(mail) = mail {
            update_entry.attrs.insert("mail".to_string(), mail.to_vec());
        }

        self.perform_patch_request(format!("/v1/person/{}", id).as_str(), update_entry)
            .await
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

    pub async fn idm_person_account_purge_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/person/{}/_attr/{}", id, attr).as_str())
            .await
    }

    pub async fn idm_person_account_primary_credential_import_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            format!("/v1/person/{}/_attr/password_import", id).as_str(),
            vec![pw.to_string()],
        )
        .await
    }

    pub async fn idm_person_account_get_credential_status(
        &self,
        id: &str,
    ) -> Result<CredentialStatus, ClientError> {
        let res: Result<CredentialStatus, ClientError> = self
            .perform_get_request(format!("/v1/person/{}/_credential/_status", id).as_str())
            .await;
        res.and_then(|cs| {
            if cs.creds.is_empty() {
                Err(ClientError::EmptyResponse)
            } else {
                Ok(cs)
            }
        })
    }

    // This helper calls through the credential update session wrappers to
    pub async fn idm_person_account_primary_credential_set_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<(), ClientError> {
        let (session_tok, status) = self.idm_account_credential_update_begin(id).await?;
        trace!(?status);

        let status = self
            .idm_account_credential_update_set_password(&session_tok, pw)
            .await?;
        trace!(?status);

        self.idm_account_credential_update_commit(&session_tok)
            .await
    }

    pub async fn idm_person_account_post_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
        pubkey: &str,
    ) -> Result<(), ClientError> {
        let sk = (tag.to_string(), pubkey.to_string());
        self.perform_post_request(format!("/v1/person/{}/_ssh_pubkeys", id).as_str(), sk)
            .await
    }

    pub async fn idm_person_account_delete_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/person/{}/_ssh_pubkeys/{}", id, tag).as_str())
            .await
    }

    pub async fn idm_person_account_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
        shell: Option<&str>,
    ) -> Result<(), ClientError> {
        let ux = AccountUnixExtend {
            shell: shell.map(str::to_string),
            gidnumber,
        };
        self.perform_post_request(format!("/v1/person/{}/_unix", id).as_str(), ux)
            .await
    }

    pub async fn idm_person_account_unix_cred_put(
        &self,
        id: &str,
        cred: &str,
    ) -> Result<(), ClientError> {
        let req = SingleStringRequest {
            value: cred.to_string(),
        };
        self.perform_put_request(
            ["/v1/person/", id, "/_unix/_credential"].concat().as_str(),
            req,
        )
        .await
    }

    pub async fn idm_person_account_unix_cred_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/person/", id, "/_unix/_credential"].concat().as_str())
            .await
    }

    pub async fn idm_account_radius_credential_get(
        &self,
        id: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/person/{}/_radius", id).as_str())
            .await
    }

    pub async fn idm_account_radius_credential_regenerate(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        self.perform_post_request(format!("/v1/person/{}/_radius", id).as_str(), ())
            .await
    }

    pub async fn idm_account_radius_credential_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/person/{}/_radius", id).as_str())
            .await
    }
}
