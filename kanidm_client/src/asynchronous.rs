use crate::{ClientError, KanidmClientBuilder, APPLICATION_JSON, KOPID};
use reqwest::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde::Serialize;

use kanidm_proto::v1::*;

#[derive(Debug)]
pub struct KanidmAsyncClient {
    pub(crate) client: reqwest::Client,
    pub(crate) addr: String,
    pub(crate) builder: KanidmClientBuilder,
    pub(crate) bearer_token: Option<String>,
}

impl KanidmAsyncClient {
    async fn perform_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let dest = [self.addr.as_str(), dest].concat();
        debug!("{:?}", dest);
        // format doesn't work in async ?!
        // let dest = format!("{}{}", self.addr, dest);

        let req_string = serde_json::to_string(&request).map_err(ClientError::JSONEncode)?;

        let response = self
            .client
            .post(dest.as_str())
            .body(req_string)
            .header(CONTENT_TYPE, APPLICATION_JSON);
        let response = if let Some(token) = &self.bearer_token {
            response.bearer_auth(token)
        } else {
            response
        };

        let response = response.send().await.map_err(ClientError::Transport)?;

        let opid = response
            .headers()
            .get(KOPID)
            .and_then(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "missing_kopid".to_string());
        debug!("opid -> {:?}", opid);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JSONDecode(e, opid))
    }

    async fn perform_put_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let dest = [self.addr.as_str(), dest].concat();
        debug!("{:?}", dest);
        // format doesn't work in async ?!
        // let dest = format!("{}{}", self.addr, dest);

        let req_string = serde_json::to_string(&request).map_err(ClientError::JSONEncode)?;

        let response = self
            .client
            .put(dest.as_str())
            .header(CONTENT_TYPE, APPLICATION_JSON);
        let response = if let Some(token) = &self.bearer_token {
            response.bearer_auth(token)
        } else {
            response
        };

        let response = response
            .body(req_string)
            .send()
            .await
            .map_err(ClientError::Transport)?;

        let opid = response
            .headers()
            .get(KOPID)
            .and_then(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "missing_kopid".to_string());

        debug!("opid -> {:?}", opid);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JSONDecode(e, opid))
    }

    async fn perform_get_request<T: DeserializeOwned>(&self, dest: &str) -> Result<T, ClientError> {
        let dest = [self.addr.as_str(), dest].concat();
        debug!("{:?}", dest);
        // let dest = format!("{}{}", self.addr, dest);
        let response = self.client.get(dest.as_str());
        let response = if let Some(token) = &self.bearer_token {
            response.bearer_auth(token)
        } else {
            response
        };

        let response = response.send().await.map_err(ClientError::Transport)?;

        let opid = response
            .headers()
            .get(KOPID)
            .and_then(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "missing_kopid".to_string());

        debug!("opid -> {:?}", opid);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JSONDecode(e, opid))
    }

    async fn perform_delete_request(&self, dest: &str) -> Result<bool, ClientError> {
        let dest = format!("{}{}", self.addr, dest);
        let response = self.client.delete(dest.as_str());
        let response = if let Some(token) = &self.bearer_token {
            response.bearer_auth(token)
        } else {
            response
        };

        let response = response.send().await.map_err(ClientError::Transport)?;

        let opid = response
            .headers()
            .get(KOPID)
            .and_then(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "missing_kopid".to_string());
        debug!("opid -> {:?}", opid);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JSONDecode(e, opid))
    }

    pub async fn auth_step_init(&self, ident: &str) -> Result<AuthState, ClientError> {
        let auth_init = AuthRequest {
            step: AuthStep::Init(ident.to_string()),
        };

        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_init).await;
        r.map(|v| v.state)
    }

    pub async fn auth_simple_password(
        &mut self,
        ident: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        let _state = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let auth_req = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Password(password.to_string())]),
        };
        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_req).await;

        let r = r?;

        match r.state {
            AuthState::Success(token) => {
                self.bearer_token = Some(token);
                Ok(())
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn auth_anonymous(&mut self) -> Result<(), ClientError> {
        // TODO #251: Check state for auth continue contains anonymous.
        // #251 will remove the need for this check.
        let _state = match self.auth_step_init("anonymous").await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let auth_anon = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Anonymous]),
        };
        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_anon).await;

        let r = r?;

        match r.state {
            AuthState::Success(token) => {
                self.bearer_token = Some(token);
                Ok(())
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn whoami(&self) -> Result<Option<(Entry, UserAuthToken)>, ClientError> {
        let whoami_dest = [self.addr.as_str(), "/v1/self"].concat();
        // format!("{}/v1/self", self.addr);
        debug!("{:?}", whoami_dest);
        let response = self
            .client
            .get(whoami_dest.as_str())
            .send()
            .await
            .map_err(ClientError::Transport)?;

        let opid = response
            .headers()
            .get(KOPID)
            .and_then(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .unwrap_or_else(|| "missing_kopid".to_string());
        debug!("opid -> {:?}", opid);

        match response.status() {
            // Continue to process.
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => return Ok(None),
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        let r: WhoamiResponse = response
            .json()
            .await
            .map_err(|e| ClientError::JSONDecode(e, opid))?;

        Ok(Some((r.youare, r.uat)))
    }

    pub async fn idm_account_unix_token_get(&self, id: &str) -> Result<UnixUserToken, ClientError> {
        // Format doesn't work in async
        // format!("/v1/account/{}/_unix/_token", id).as_str()
        self.perform_get_request(["/v1/account/", id, "/_unix/_token"].concat().as_str())
            .await
    }

    pub async fn idm_group_unix_token_get(&self, id: &str) -> Result<UnixGroupToken, ClientError> {
        // Format doesn't work in async
        // format!("/v1/account/{}/_unix/_token", id).as_str()
        self.perform_get_request(["/v1/group/", id, "/_unix/_token"].concat().as_str())
            .await
    }

    pub async fn idm_account_delete(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(["/v1/account/", id].concat().as_str())
            .await
    }

    pub async fn idm_group_delete(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(["/v1/group/", id].concat().as_str())
            .await
    }

    pub async fn idm_account_unix_cred_put(
        &self,
        id: &str,
        cred: &str,
    ) -> Result<bool, ClientError> {
        let req = SingleStringRequest {
            value: cred.to_string(),
        };
        self.perform_put_request(
            ["/v1/account/", id, "/_unix/_credential"].concat().as_str(),
            req,
        )
        .await
    }

    pub async fn idm_account_unix_cred_delete(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(["/v1/account/", id, "/_unix/_credential"].concat().as_str())
            .await
    }

    pub async fn idm_account_unix_cred_verify(
        &self,
        id: &str,
        cred: &str,
    ) -> Result<Option<UnixUserToken>, ClientError> {
        let req = SingleStringRequest {
            value: cred.to_string(),
        };
        self.perform_post_request(["/v1/account/", id, "/_unix/_auth"].concat().as_str(), req)
            .await
    }

    pub async fn idm_group_add_members(
        &self,
        id: &str,
        members: Vec<&str>,
    ) -> Result<bool, ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(["/v1/group/", id, "/_attr/member"].concat().as_str(), m)
            .await
    }
}
