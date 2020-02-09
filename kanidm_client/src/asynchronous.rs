use crate::{ClientError, KanidmClientBuilder};
use reqwest;
use serde::de::DeserializeOwned;
use serde::Serialize;

use kanidm_proto::v1::*;

#[derive(Debug)]
pub struct KanidmAsyncClient {
    pub(crate) client: reqwest::Client,
    pub(crate) addr: String,
    pub(crate) builder: KanidmClientBuilder,
}

impl KanidmAsyncClient {
    async fn perform_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let dest = format!("{}{}", self.addr, dest);

        let req_string = serde_json::to_string(&request).unwrap();

        let response = self
            .client
            .post(dest.as_str())
            .body(req_string)
            .send()
            .await
            .map_err(ClientError::Transport)?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect, response.json().await.ok())),
        }

        // TODO: What about errors
        let r: T = response.json().await.unwrap();

        Ok(r)
    }

    pub async fn auth_step_init(
        &self,
        ident: &str,
        appid: Option<&str>,
    ) -> Result<AuthState, ClientError> {
        let auth_init = AuthRequest {
            step: AuthStep::Init(ident.to_string(), appid.map(|s| s.to_string())),
        };

        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_init).await;
        r.map(|v| v.state)
    }

    pub async fn auth_anonymous(&self) -> Result<UserAuthToken, ClientError> {
        // TODO: Check state for auth continue contains anonymous.
        let _state = match self.auth_step_init("anonymous", None).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let auth_anon = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Anonymous]),
        };
        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_anon).await;

        let r = r?;

        match r.state {
            AuthState::Success(uat) => {
                debug!("==> Authed as uat; {:?}", uat);
                Ok(uat)
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn whoami(&self) -> Result<Option<(Entry, UserAuthToken)>, ClientError> {
        let whoami_dest = format!("{}/v1/self", self.addr);
        let response = self.client.get(whoami_dest.as_str()).send().await.unwrap();

        match response.status() {
            // Continue to process.
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => return Ok(None),
            unexpect => return Err(ClientError::Http(unexpect, response.json().await.ok())),
        }

        let r: WhoamiResponse =
            serde_json::from_str(response.text().await.unwrap().as_str()).unwrap();

        Ok(Some((r.youare, r.uat)))
    }
}
