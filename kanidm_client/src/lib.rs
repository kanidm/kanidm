#![deny(warnings)]
#![warn(unused_extern_crates)]

#[macro_use]
extern crate log;

use reqwest;
use reqwest::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_derive::Deserialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use toml;
use uuid::Uuid;

use kanidm_proto::v1::{
    AccountUnixExtend, AuthCredential, AuthRequest, AuthResponse, AuthState, AuthStep,
    CreateRequest, DeleteRequest, Entry, Filter, GroupUnixExtend, ModifyList, ModifyRequest,
    OperationError, OperationResponse, RadiusAuthToken, SearchRequest, SearchResponse,
    SetCredentialRequest, SetCredentialResponse, SingleStringRequest, TOTPSecret, UnixGroupToken,
    UnixUserToken, UserAuthToken, WhoamiResponse,
};
use serde_json;

pub mod asynchronous;

use crate::asynchronous::KanidmAsyncClient;

pub static APPLICATION_JSON: &'static str = "application/json";

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    Http(reqwest::StatusCode, Option<OperationError>),
    Transport(reqwest::Error),
    AuthenticationFailed,
    JsonParse,
    EmptyResponse,
    TOTPVerifyFailed(Uuid, TOTPSecret),
}

#[derive(Debug, Deserialize)]
struct KanidmClientConfig {
    uri: Option<String>,
    verify_ca: Option<bool>,
    verify_hostnames: Option<bool>,
    ca_path: Option<String>,
    // Should we add username/pw later? They could be part of the builder
    // process ...
}

#[derive(Debug, Clone, Default)]
pub struct KanidmClientBuilder {
    address: Option<String>,
    verify_ca: bool,
    verify_hostnames: bool,
    ca: Option<reqwest::Certificate>,
    connect_timeout: Option<u64>,
}

impl KanidmClientBuilder {
    pub fn new() -> Self {
        KanidmClientBuilder {
            address: None,
            verify_ca: true,
            verify_hostnames: true,
            ca: None,
            connect_timeout: None,
        }
    }

    fn parse_certificate(ca_path: &str) -> Result<reqwest::Certificate, ()> {
        let mut buf = Vec::new();
        // TODO: Handle these errors better, or at least provide diagnostics?
        let mut f = File::open(ca_path).map_err(|_| ())?;
        f.read_to_end(&mut buf).map_err(|_| ())?;
        reqwest::Certificate::from_pem(&buf).map_err(|_| ())
    }

    fn apply_config_options(self, kcc: KanidmClientConfig) -> Result<Self, ()> {
        let KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
        } = self;
        // Process and apply all our options if they exist.
        let address = match kcc.uri {
            Some(uri) => Some(uri),
            None => address,
        };
        let verify_ca = kcc.verify_ca.unwrap_or_else(|| verify_ca);
        let verify_hostnames = kcc.verify_hostnames.unwrap_or_else(|| verify_hostnames);
        let ca = match kcc.ca_path {
            Some(ca_path) => Some(Self::parse_certificate(ca_path.as_str())?),
            None => ca,
        };

        Ok(KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
        })
    }

    pub fn read_options_from_optional_config<P: AsRef<Path>>(
        self,
        config_path: P,
    ) -> Result<Self, ()> {
        // If the file does not exist, we skip this function.
        let mut f = match File::open(config_path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Unabled to open config file [{:?}], skipping ...", e);
                return Ok(self);
            }
        };

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .map_err(|e| eprintln!("{:?}", e))?;

        let config: KanidmClientConfig =
            toml::from_str(contents.as_str()).map_err(|e| eprintln!("{:?}", e))?;

        self.apply_config_options(config)
    }

    pub fn address(self, address: String) -> Self {
        KanidmClientBuilder {
            address: Some(address),
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
        }
    }

    pub fn danger_accept_invalid_hostnames(self, accept_invalid_hostnames: bool) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            // We have to flip the bool state here due to english language.
            verify_hostnames: !accept_invalid_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
        }
    }

    pub fn danger_accept_invalid_certs(self, accept_invalid_certs: bool) -> Self {
        KanidmClientBuilder {
            address: self.address,
            // We have to flip the bool state here due to english language.
            verify_ca: !accept_invalid_certs,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
        }
    }

    pub fn connect_timeout(self, secs: u64) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: Some(secs),
        }
    }

    pub fn add_root_certificate_filepath(self, ca_path: &str) -> Result<Self, ()> {
        //Okay we have a ca to add. Let's read it in and setup.
        let ca = Self::parse_certificate(ca_path)?;

        Ok(KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: Some(ca),
            connect_timeout: self.connect_timeout,
        })
    }

    // Consume self and return a client.
    pub fn build(self) -> Result<KanidmClient, reqwest::Error> {
        // Errghh, how to handle this cleaner.
        let address = match &self.address {
            Some(a) => a.clone(),
            None => {
                eprintln!("uri (-H) missing, can not proceed");
                unimplemented!();
            }
        };

        let client_builder = reqwest::blocking::Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_hostnames(!self.verify_hostnames)
            .danger_accept_invalid_certs(!self.verify_ca);

        let client_builder = match &self.ca {
            Some(cert) => client_builder.add_root_certificate(cert.clone()),
            None => client_builder,
        };

        let client_builder = match &self.connect_timeout {
            Some(secs) => client_builder
                .connect_timeout(Duration::from_secs(*secs))
                .timeout(Duration::from_secs(*secs)),
            None => client_builder,
        };

        let client = client_builder.build()?;

        Ok(KanidmClient {
            client,
            addr: address,
            builder: self,
        })
    }

    pub fn build_async(self) -> Result<KanidmAsyncClient, reqwest::Error> {
        // Errghh, how to handle this cleaner.
        let address = match &self.address {
            Some(a) => a.clone(),
            None => {
                eprintln!("uri (-H) missing, can not proceed");
                unimplemented!();
            }
        };

        let client_builder = reqwest::Client::builder()
            .cookie_store(true)
            .danger_accept_invalid_hostnames(!self.verify_hostnames)
            .danger_accept_invalid_certs(!self.verify_ca);

        let client_builder = match &self.ca {
            Some(cert) => client_builder.add_root_certificate(cert.clone()),
            None => client_builder,
        };

        let client_builder = match &self.connect_timeout {
            Some(secs) => client_builder
                .connect_timeout(Duration::from_secs(*secs))
                .timeout(Duration::from_secs(*secs)),
            None => client_builder,
        };

        let client = client_builder.build()?;

        Ok(KanidmAsyncClient {
            client,
            addr: address,
            builder: self,
        })
    }
}

#[derive(Debug)]
pub struct KanidmClient {
    client: reqwest::blocking::Client,
    addr: String,
    builder: KanidmClientBuilder,
}

impl KanidmClient {
    pub fn new_session(&self) -> Result<Self, reqwest::Error> {
        // Copy our builder, and then just process it.
        let builder = self.builder.clone();
        builder.build()
    }

    pub fn logout(&mut self) -> Result<(), reqwest::Error> {
        // hack - we have to replace our reqwest client because that's the only way
        // to currently flush the cookie store. To achieve this we need to rebuild
        // and then destructure.

        let builder = self.builder.clone();
        let KanidmClient { mut client, .. } = builder.build()?;

        std::mem::swap(&mut self.client, &mut client);
        Ok(())
    }

    fn perform_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let dest = format!("{}{}", self.addr, dest);

        let req_string = serde_json::to_string(&request).unwrap();

        let response = self
            .client
            .post(dest.as_str())
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(req_string)
            .send()
            .map_err(ClientError::Transport)?;

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

        let response = self
            .client
            .put(dest.as_str())
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(req_string)
            .send()
            .map_err(ClientError::Transport)?;

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
        let response = self
            .client
            .get(dest.as_str())
            .send()
            .map_err(ClientError::Transport)?;

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
        let response = self
            .client
            .delete(dest.as_str())
            .send()
            .map_err(ClientError::Transport)?;

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
        let response = self.client.get(whoami_dest.as_str()).send().unwrap();

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

    pub fn auth_password_totp(
        &self,
        ident: &str,
        password: &str,
        totp: u32,
    ) -> Result<UserAuthToken, ClientError> {
        let _state = match self.auth_step_init(ident, None) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let auth_req = AuthRequest {
            step: AuthStep::Creds(vec![
                AuthCredential::TOTP(totp),
                AuthCredential::Password(password.to_string()),
            ]),
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
        let sr = SearchRequest { filter };
        let r: Result<SearchResponse, _> = self.perform_post_request("/v1/raw/search", sr);
        r.map(|v| v.entries)
    }

    // create
    pub fn create(&self, entries: Vec<Entry>) -> Result<(), ClientError> {
        let c = CreateRequest { entries };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/create", c);
        r.map(|_| ())
    }

    // modify
    pub fn modify(&self, filter: Filter, modlist: ModifyList) -> Result<(), ClientError> {
        let mr = ModifyRequest { filter, modlist };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/modify", mr);
        r.map(|_| ())
    }

    // delete
    pub fn delete(&self, filter: Filter) -> Result<(), ClientError> {
        let dr = DeleteRequest { filter };
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

    pub fn idm_group_get_members(&self, id: &str) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(format!("/v1/group/{}/_attr/member", id).as_str())
    }

    pub fn idm_group_set_members(&self, id: &str, members: Vec<&str>) -> Result<(), ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(format!("/v1/group/{}/_attr/member", id).as_str(), m)
    }

    pub fn idm_group_add_members(&self, id: &str, members: Vec<&str>) -> Result<(), ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(format!("/v1/group/{}/_attr/member", id).as_str(), m)
    }

    /*
    pub fn idm_group_remove_member(&self, id: &str, member: &str) -> Result<(), ClientError> {
        unimplemented!();
    }
    */

    pub fn idm_group_purge_members(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/group/{}/_attr/member", id).as_str())
    }

    pub fn idm_group_unix_token_get(&self, id: &str) -> Result<UnixGroupToken, ClientError> {
        self.perform_get_request(format!("/v1/group/{}/_unix/_token", id).as_str())
    }

    pub fn idm_group_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
    ) -> Result<(), ClientError> {
        let gx = GroupUnixExtend {
            gidnumber: gidnumber,
        };
        self.perform_post_request(format!("/v1/group/{}/_unix", id).as_str(), gx)
    }

    pub fn idm_group_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/group/{}", id).as_str())
    }

    pub fn idm_group_create(&self, name: &str) -> Result<(), ClientError> {
        let mut new_group = Entry {
            attrs: BTreeMap::new(),
        };
        new_group
            .attrs
            .insert("name".to_string(), vec![name.to_string()]);
        self.perform_post_request("/v1/group", new_group)
            .map(|_: OperationResponse| ())
    }

    // ==== accounts
    pub fn idm_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/account")
    }

    pub fn idm_account_create(&self, name: &str, dn: &str) -> Result<(), ClientError> {
        let mut new_acct = Entry {
            attrs: BTreeMap::new(),
        };
        new_acct
            .attrs
            .insert("name".to_string(), vec![name.to_string()]);
        new_acct
            .attrs
            .insert("displayname".to_string(), vec![dn.to_string()]);
        self.perform_post_request("/v1/account", new_acct)
            .map(|_: OperationResponse| ())
    }

    pub fn idm_account_set_displayname(&self, id: &str, dn: &str) -> Result<(), ClientError> {
        self.perform_put_request(
            format!("/v1/account/{}/_attr/displayname", id).as_str(),
            vec![dn.to_string()],
        )
    }

    pub fn idm_account_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/account/{}", id).as_str())
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
    ) -> Result<SetCredentialResponse, ClientError> {
        let r = SetCredentialRequest::Password(pw.to_string());
        self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        )
    }

    pub fn idm_account_primary_credential_import_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            format!("/v1/account/{}/_attr/password_import", id).as_str(),
            vec![pw.to_string()],
        )
    }

    pub fn idm_account_primary_credential_set_generated(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        let r = SetCredentialRequest::GeneratePassword;
        let res: Result<SetCredentialResponse, ClientError> = self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        );
        match res {
            Ok(SetCredentialResponse::Token(p)) => Ok(p),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    // Reg intent for totp
    pub fn idm_account_primary_credential_generate_totp(
        &self,
        id: &str,
        label: &str,
    ) -> Result<(Uuid, TOTPSecret), ClientError> {
        let r = SetCredentialRequest::TOTPGenerate(label.to_string());
        let res: Result<SetCredentialResponse, ClientError> = self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        );
        match res {
            Ok(SetCredentialResponse::TOTPCheck(u, s)) => Ok((u, s)),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    // Verify the totp
    pub fn idm_account_primary_credential_verify_totp(
        &self,
        id: &str,
        otp: u32,
        session: Uuid,
    ) -> Result<(), ClientError> {
        let r = SetCredentialRequest::TOTPVerify(session, otp);
        let res: Result<SetCredentialResponse, ClientError> = self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        );
        match res {
            Ok(SetCredentialResponse::Success) => Ok(()),
            Ok(SetCredentialResponse::TOTPCheck(u, s)) => Err(ClientError::TOTPVerifyFailed(u, s)),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
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

    pub fn idm_account_radius_token_get(&self, id: &str) -> Result<RadiusAuthToken, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_radius/_token", id).as_str())
    }

    pub fn idm_account_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
        shell: Option<&str>,
    ) -> Result<(), ClientError> {
        let ux = AccountUnixExtend {
            shell: shell.map(|s| s.to_string()),
            gidnumber: gidnumber,
        };
        self.perform_post_request(format!("/v1/account/{}/_unix", id).as_str(), ux)
    }

    pub fn idm_account_unix_token_get(&self, id: &str) -> Result<UnixUserToken, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_unix/_token", id).as_str())
    }

    pub fn idm_account_unix_cred_put(&self, id: &str, cred: &str) -> Result<(), ClientError> {
        let req = SingleStringRequest {
            value: cred.to_string(),
        };
        self.perform_put_request(
            format!("/v1/account/{}/_unix/_credential", id).as_str(),
            req,
        )
    }

    pub fn idm_account_unix_cred_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/account/{}/_unix/_credential", id).as_str())
    }

    pub fn idm_account_unix_cred_verify(
        &self,
        id: &str,
        cred: &str,
    ) -> Result<Option<UnixUserToken>, ClientError> {
        let req = SingleStringRequest {
            value: cred.to_string(),
        };
        self.perform_post_request(format!("/v1/account/{}/_unix/_auth", id).as_str(), req)
    }

    pub fn idm_account_get_ssh_pubkeys(&self, id: &str) -> Result<Vec<String>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_ssh_pubkeys", id).as_str())
    }

    pub fn idm_account_post_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
        pubkey: &str,
    ) -> Result<(), ClientError> {
        let sk = (tag.to_string(), pubkey.to_string());
        self.perform_post_request(format!("/v1/account/{}/_ssh_pubkeys", id).as_str(), sk)
    }

    pub fn idm_account_person_extend(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(format!("/v1/account/{}/_person/_extend", id).as_str(), ())
    }

    /*
    pub fn idm_account_rename_ssh_pubkey(&self, id: &str, oldtag: &str, newtag: &str) -> Result<(), ClientError> {
        self.perform_put_request(format!("/v1/account/{}/_ssh_pubkeys/{}", id, oldtag).as_str(), newtag.to_string())
    }
    */

    pub fn idm_account_get_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_ssh_pubkeys/{}", id, tag).as_str())
    }

    pub fn idm_account_delete_ssh_pubkey(&self, id: &str, tag: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/account/{}/_ssh_pubkeys/{}", id, tag).as_str())
    }

    // ==== domain_info (aka domain)
    pub fn idm_domain_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/domain")
    }

    pub fn idm_domain_get(&self, id: &str) -> Result<Entry, ClientError> {
        self.perform_get_request(format!("/v1/domain/{}", id).as_str())
    }

    // pub fn idm_domain_get_attr
    pub fn idm_domain_get_ssid(&self, id: &str) -> Result<String, ClientError> {
        self.perform_get_request(format!("/v1/domain/{}/_attr/domain_ssid", id).as_str())
            .and_then(|mut r: Vec<String>| Ok(r.pop().unwrap()))
    }

    // pub fn idm_domain_put_attr
    pub fn idm_domain_set_ssid(&self, id: &str, ssid: &str) -> Result<(), ClientError> {
        self.perform_put_request(
            format!("/v1/domain/{}/_attr/domain_ssid", id).as_str(),
            vec![ssid.to_string()],
        )
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

    // ==== recycle bin
    pub fn recycle_bin_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/recycle_bin")
    }

    pub fn recycle_bin_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/recycle_bin/{}", id).as_str())
    }

    pub fn recycle_bin_revive(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(format!("/v1/recycle_bin/{}/_revive", id).as_str(), ())
    }
}
