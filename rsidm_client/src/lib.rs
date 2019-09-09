#![deny(warnings)]
#![warn(unused_extern_crates)]

#[macro_use]
extern crate log;

use serde_json;

use reqwest;

use rsidm_proto::v1::{
    AuthCredential, AuthRequest, AuthResponse, AuthState, AuthStep, CreateRequest, Entry,
    OperationResponse, UserAuthToken, WhoamiResponse,
};

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    Http(reqwest::StatusCode),
    Transport(reqwest::Error),
    AuthenticationFailed,
}

#[derive(Debug)]
pub struct RsidmClient {
    client: reqwest::Client,
    addr: String,
}

impl RsidmClient {
    pub fn new(addr: &str) -> Self {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("Unexpected reqwest builder failure!");
        RsidmClient {
            client: client,
            addr: addr.to_string(),
        }
    }

    fn auth_step_init(&self, ident: &str, appid: Option<&str>) -> Result<AuthState, ClientError> {
        // TODO: Way to avoid formatting so much?
        let auth_dest = format!("{}/v1/auth", self.addr);

        let auth_init = AuthRequest {
            step: AuthStep::Init(ident.to_string(), appid.map(|s| s.to_string())),
        };

        // Handle this!
        let mut response = self
            .client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_init).expect("Generated invalid initstep?!"))
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect)),
        }
        // Check that we got the next step
        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();

        Ok(r.state)
    }

    // auth
    pub fn auth_anonymous(&self) -> Result<UserAuthToken, ClientError> {
        let _state = match self.auth_step_init("anonymous", None) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        // TODO: Avoid creating this so much?
        let auth_dest = format!("{}/v1/auth", self.addr);

        // Check state for auth continue contains anonymous.

        let auth_anon = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Anonymous]),
        };

        let mut response = self
            .client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_anon).unwrap())
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect)),
        }
        // Check that we got the next step
        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();

        match r.state {
            AuthState::Success(uat) => {
                debug!("==> Authed as uat; {:?}", uat);
                Ok(uat)
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub fn auth_simple_password(
        &self,
        ident: &str,
        password: &str,
    ) -> Result<UserAuthToken, ClientError> {
        // TODO: Way to avoid formatting so much?
        let auth_dest = format!("{}/v1/auth", self.addr);

        let _state = match self.auth_step_init(ident, None) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        // Send the credentials required now
        let auth_req = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Password(password.to_string())]),
        };

        let mut response = self
            .client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_req).unwrap())
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect)),
        }

        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();

        match r.state {
            AuthState::Success(uat) => {
                debug!("==> Authed as uat; {:?}", uat);
                Ok(uat)
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    // whoami
    pub fn whoami(&self) -> Result<Option<(Entry, UserAuthToken)>, ClientError> {
        let whoami_dest = format!("{}/v1/whoami", self.addr);
        let mut response = self.client.get(whoami_dest.as_str()).send().unwrap();
        // https://docs.rs/reqwest/0.9.15/reqwest/struct.Response.html

        match response.status() {
            // Continue to process.
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => return Ok(None),
            unexpect => return Err(ClientError::Http(unexpect)),
        }

        let r: WhoamiResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();

        Ok(Some((r.youare, r.uat)))
    }

    // search
    // create
    pub fn create(&self, entries: Vec<Entry>) -> Result<(), ClientError> {
        let c = CreateRequest { entries: entries };

        // TODO: Avoid formatting this so much!
        let dest = format!("{}/v1/create", self.addr);

        let mut response = self
            .client
            .post(dest.as_str())
            .body(serde_json::to_string(&c).unwrap())
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect)),
        }

        // TODO: What about errors
        let _r: OperationResponse =
            serde_json::from_str(response.text().unwrap().as_str()).unwrap();
        Ok(())
    }

    // modify
    //
}
