use crate::{ClientError, KanidmClient};
use kanidm_proto::constants::{
    ATTR_DISPLAYNAME, ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE,
    ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE, ATTR_OAUTH2_RS_NAME, ATTR_OAUTH2_RS_ORIGIN,
};
use kanidm_proto::internal::ImageValue;
use kanidm_proto::v1::Entry;
use reqwest::multipart;
use std::collections::BTreeMap;

impl KanidmClient {
    // ==== Oauth2 resource server configuration
    #[instrument(level = "debug")]
    pub async fn idm_oauth2_rs_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/oauth2").await
    }

    pub async fn idm_oauth2_rs_basic_create(
        &self,
        name: &str,
        displayname: &str,
        origin: &str,
    ) -> Result<(), ClientError> {
        let mut new_oauth2_rs = Entry::default();
        new_oauth2_rs
            .attrs
            .insert(ATTR_OAUTH2_RS_NAME.to_string(), vec![name.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_OAUTH2_RS_ORIGIN.to_string(), vec![origin.to_string()]);
        self.perform_post_request("/v1/oauth2/_basic", new_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_public_create(
        &self,
        name: &str,
        displayname: &str,
        origin: &str,
    ) -> Result<(), ClientError> {
        let mut new_oauth2_rs = Entry::default();
        new_oauth2_rs
            .attrs
            .insert(ATTR_OAUTH2_RS_NAME.to_string(), vec![name.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_OAUTH2_RS_ORIGIN.to_string(), vec![origin.to_string()]);
        self.perform_post_request("/v1/oauth2/_public", new_oauth2_rs)
            .await
    }

    // TODO: the "id" here is actually the *name* not the uuid of the entry...
    pub async fn idm_oauth2_rs_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/{}", id).as_str())
            .await
    }

    pub async fn idm_oauth2_rs_get_basic_secret(
        &self,
        id: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/{}/_basic_secret", id).as_str())
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn idm_oauth2_rs_update(
        &self,
        id: &str,
        name: Option<&str>,
        displayname: Option<&str>,
        origin: Option<&str>,
        landing: Option<&str>,
        reset_secret: bool,
        reset_token_key: bool,
        reset_sign_key: bool,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };

        if let Some(newname) = name {
            update_oauth2_rs
                .attrs
                .insert(ATTR_OAUTH2_RS_NAME.to_string(), vec![newname.to_string()]);
        }
        if let Some(newdisplayname) = displayname {
            update_oauth2_rs.attrs.insert(
                ATTR_DISPLAYNAME.to_string(),
                vec![newdisplayname.to_string()],
            );
        }
        if let Some(neworigin) = origin {
            update_oauth2_rs.attrs.insert(
                ATTR_OAUTH2_RS_ORIGIN.to_string(),
                vec![neworigin.to_string()],
            );
        }
        if let Some(newlanding) = landing {
            update_oauth2_rs.attrs.insert(
                "oauth2_rs_origin_landing".to_string(),
                vec![newlanding.to_string()],
            );
        }
        if reset_secret {
            update_oauth2_rs
                .attrs
                .insert("oauth2_rs_basic_secret".to_string(), Vec::new());
        }
        if reset_token_key {
            update_oauth2_rs
                .attrs
                .insert("oauth2_rs_token_key".to_string(), Vec::new());
        }
        if reset_sign_key {
            update_oauth2_rs
                .attrs
                .insert("es256_private_key_der".to_string(), Vec::new());
            update_oauth2_rs
                .attrs
                .insert("rs256_private_key_der".to_string(), Vec::new());
        }
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_update_scope_map(
        &self,
        id: &str,
        group: &str,
        scopes: Vec<&str>,
    ) -> Result<(), ClientError> {
        let scopes: Vec<String> = scopes.into_iter().map(str::to_string).collect();
        self.perform_post_request(
            format!("/v1/oauth2/{}/_scopemap/{}", id, group).as_str(),
            scopes,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_scope_map(
        &self,
        id: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{}/_scopemap/{}", id, group).as_str())
            .await
    }

    pub async fn idm_oauth2_rs_update_sup_scope_map(
        &self,
        id: &str,
        group: &str,
        scopes: Vec<&str>,
    ) -> Result<(), ClientError> {
        let scopes: Vec<String> = scopes.into_iter().map(str::to_string).collect();
        self.perform_post_request(
            format!("/v1/oauth2/{}/_sup_scopemap/{}", id, group).as_str(),
            scopes,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_sup_scope_map(
        &self,
        id: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{}/_sup_scopemap/{}", id, group).as_str())
            .await
    }

    pub async fn idm_oauth2_rs_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/oauth2/", id].concat().as_str())
            .await
    }

    pub async fn idm_oauth2_rs_update_image(
        &self,
        id: &str,
        image: ImageValue,
    ) -> Result<(), ClientError> {
        let url = self.make_url(&format!("/v1/oauth2/{}/_image", id));

        let file_content_type = image.filetype.as_content_type_str();

        let file_data = multipart::Part::bytes(image.contents.clone())
            .file_name(image.filename)
            .mime_str(file_content_type)
            .unwrap();

        let form = multipart::Form::new().part("image", file_data);

        // send it
        let response = self.client.post(url).multipart(form);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };
        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        Ok(())
    }

    pub async fn idm_oauth2_rs_enable_pkce(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE.to_string(),
            Vec::new(),
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_pkce(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_legacy_crypto(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_legacy_crypto(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_prefer_short_username(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            "oauth2_prefer_short_username".to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_prefer_spn_username(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            "oauth2_prefer_short_username".to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }
}
