#![deny(warnings)]
#![warn(unused_extern_crates)]

#[macro_use]
extern crate log;

use reqwest;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::io::Read;

use kanidm_proto::v1::{
    AuthCredential, AuthRequest, AuthResponse, AuthState, AuthStep, CreateRequest, DeleteRequest,
    Entry, Filter, ModifyList, ModifyRequest, OperationError, OperationResponse, SearchRequest,
    SearchResponse, SetAuthCredential, SingleStringRequest, UserAuthToken, WhoamiResponse,
};
use serde_json;

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    Http(reqwest::StatusCode, Option<OperationError>),
    Transport(reqwest::Error),
    AuthenticationFailed,
    JsonParse,
    EmptyResponse,
}

#[derive(Debug)]
pub struct KanidmClient {
    client: reqwest::Client,
    addr: String,
    ca: Option<reqwest::Certificate>,
}

impl KanidmClient {
    pub fn new(addr: &str, ca: Option<&str>) -> Self {
        let ca = ca.map(|ca_path| {
            //Okay we have a ca to add. Let's read it in and setup.
            let mut buf = Vec::new();
            // TODO: Better than expect?
            let mut f = File::open(ca_path).expect("Failed to open ca");
            f.read_to_end(&mut buf).expect("Failed to read ca");
            reqwest::Certificate::from_pem(&buf).expect("Failed to parse ca")
        });

        let client = Self::build_reqwest(&ca).expect("Unexpected reqwest builder failure!");

        KanidmClient {
            client: client,
            addr: addr.to_string(),
            ca: ca,
        }
    }

    pub fn new_session(&self) -> Self {
        let new_client =
            Self::build_reqwest(&self.ca).expect("Unexpected reqwest builder failure!");

        KanidmClient {
            client: new_client,
            addr: self.addr.clone(),
            ca: self.ca.clone(),
        }
    }

    fn build_reqwest(ca: &Option<reqwest::Certificate>) -> Result<reqwest::Client, reqwest::Error> {
        let client_builder = reqwest::Client::builder().cookie_store(true);

        let client_builder = match ca {
            Some(cert) => client_builder.add_root_certificate(cert.clone()),
            None => client_builder,
        };

        client_builder.build()
    }

    pub fn logout(&mut self) -> Result<(), reqwest::Error> {
        let mut r_client = Self::build_reqwest(&self.ca)?;
        std::mem::swap(&mut self.client, &mut r_client);
        Ok(())
    }

    fn perform_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let dest = format!("{}{}", self.addr, dest);

        let req_string = serde_json::to_string(&request).unwrap();

        let mut response = self
            .client
            .post(dest.as_str())
            .body(req_string)
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect, response.json().ok())),
        }

        // TODO: What about errors
        let r: T = response.json().unwrap();

        Ok(r)
    }

    fn perform_put_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let dest = format!("{}{}", self.addr, dest);

        let req_string = serde_json::to_string(&request).unwrap();

        let mut response = self
            .client
            .put(dest.as_str())
            .body(req_string)
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect, response.json().ok())),
        }

        // TODO: What about errors
        let r: T = response.json().unwrap();

        Ok(r)
    }

    fn perform_get_request<T: DeserializeOwned>(&self, dest: &str) -> Result<T, ClientError> {
        let dest = format!("{}{}", self.addr, dest);
        let mut response = self
            .client
            .get(dest.as_str())
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect, response.json().ok())),
        }

        // TODO: What about errors
        let r: T = response.json().unwrap();

        Ok(r)
    }

    fn perform_delete_request(&self, dest: &str) -> Result<(), ClientError> {
        let dest = format!("{}{}", self.addr, dest);
        let mut response = self
            .client
            .delete(dest.as_str())
            .send()
            .map_err(|e| ClientError::Transport(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => return Err(ClientError::Http(unexpect, response.json().ok())),
        }

        Ok(())
    }

    // whoami
    // Can't use generic get due to possible un-auth case.
    pub fn whoami(&self) -> Result<Option<(Entry, UserAuthToken)>, ClientError> {
        let whoami_dest = format!("{}/v1/self", self.addr);
        let mut response = self.client.get(whoami_dest.as_str()).send().unwrap();

        match response.status() {
            // Continue to process.
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => return Ok(None),
            unexpect => return Err(ClientError::Http(unexpect, response.json().ok())),
        }

        let r: WhoamiResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();

        Ok(Some((r.youare, r.uat)))
    }

    // auth
    pub fn auth_anonymous(&self) -> Result<UserAuthToken, ClientError> {
        // TODO: Check state for auth continue contains anonymous.
        let _state = match self.auth_step_init("anonymous", None) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let auth_anon = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Anonymous]),
        };
        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_anon);

        let r = r?;

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
        let _state = match self.auth_step_init(ident, None) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let auth_req = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Password(password.to_string())]),
        };
        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_req);

        let r = r?;

        match r.state {
            AuthState::Success(uat) => {
                debug!("==> Authed as uat; {:?}", uat);
                Ok(uat)
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    // search
    pub fn search(&self, filter: Filter) -> Result<Vec<Entry>, ClientError> {
        let sr = SearchRequest { filter: filter };
        let r: Result<SearchResponse, _> = self.perform_post_request("/v1/raw/search", sr);
        r.map(|v| v.entries)
    }

    // create
    pub fn create(&self, entries: Vec<Entry>) -> Result<(), ClientError> {
        let c = CreateRequest { entries: entries };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/create", c);
        r.map(|_| ())
    }

    // modify
    pub fn modify(&self, filter: Filter, modlist: ModifyList) -> Result<(), ClientError> {
        let mr = ModifyRequest {
            filter: filter,
            modlist: modlist,
        };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/modify", mr);
        r.map(|_| ())
    }

    // delete
    pub fn delete(&self, filter: Filter) -> Result<(), ClientError> {
        let dr = DeleteRequest { filter: filter };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/delete", dr);
        r.map(|_| ())
    }

    // === idm actions here ==
    pub fn idm_account_set_password(&self, cleartext: String) -> Result<(), ClientError> {
        let s = SingleStringRequest { value: cleartext };

        let r: Result<OperationResponse, _> =
            self.perform_post_request("/v1/self/_credential/primary/set_password", s);
        r.map(|_| ())
    }

    pub fn auth_step_init(
        &self,
        ident: &str,
        appid: Option<&str>,
    ) -> Result<AuthState, ClientError> {
        let auth_init = AuthRequest {
            step: AuthStep::Init(ident.to_string(), appid.map(|s| s.to_string())),
        };

        let r: Result<AuthResponse, _> = self.perform_post_request("/v1/auth", auth_init);
        r.map(|v| v.state)
    }

    // ===== GROUPS
    pub fn idm_group_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/group")
    }

    pub fn idm_group_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/group/{}", id).as_str())
    }

    // ==== accounts
    pub fn idm_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/account")
    }

    pub fn idm_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}", id).as_str())
    }

    // different ways to set the primary credential?
    // not sure how to best expose this.
    pub fn idm_account_primary_credential_set_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<(), ClientError> {
        let r = SetAuthCredential::Password(pw.to_string());
        let res: Result<Option<String>, _> = self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        );
        res.map(|_| ())
    }

    pub fn idm_account_primary_credential_set_generated(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        let r = SetAuthCredential::GeneratePassword;
        self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        )
        .and_then(|v| match v {
            Some(p) => Ok(p),
            None => Err(ClientError::EmptyResponse),
        })
    }

    pub fn idm_account_radius_credential_get(
        &self,
        id: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_radius", id).as_str())
    }

    pub fn idm_account_radius_credential_regenerate(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        self.perform_post_request(format!("/v1/account/{}/_radius", id).as_str(), ())
    }

    pub fn idm_account_radius_credential_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/account/{}/_radius", id).as_str())
    }

    // ==== schema
    pub fn idm_schema_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema")
    }

    pub fn idm_schema_attributetype_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema/attributetype")
    }

    pub fn idm_schema_attributetype_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/schema/attributetype/{}", id).as_str())
    }

    pub fn idm_schema_classtype_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema/classtype")
    }

    pub fn idm_schema_classtype_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/schema/classtype/{}", id).as_str())
    }
}
