use crate::{ClientError, KanidmClientBuilder, APPLICATION_JSON, KOPID, KSESSIONID};
use reqwest::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet as Set;
use uuid::Uuid;

use webauthn_rs::proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use kanidm_proto::v1::*;

#[derive(Debug)]
pub struct KanidmAsyncClient {
    pub(crate) client: reqwest::Client,
    pub(crate) addr: String,
    pub(crate) origin: String,
    pub(crate) builder: KanidmClientBuilder,
    pub(crate) bearer_token: Option<String>,
    pub(crate) auth_session_id: Option<String>,
}

impl KanidmAsyncClient {
    pub fn get_origin(&self) -> &str {
        self.origin.as_str()
    }

    pub fn set_token(&mut self, new_token: String) {
        let mut new_token = Some(new_token);
        std::mem::swap(&mut self.bearer_token, &mut new_token);
    }

    pub fn get_token(&self) -> Option<&str> {
        self.bearer_token.as_deref()
    }

    pub fn new_session(&self) -> Result<Self, reqwest::Error> {
        // Copy our builder, and then just process it.
        let builder = self.builder.clone();
        builder.build_async()
    }

    pub fn logout(&mut self) -> Result<(), reqwest::Error> {
        // hack - we have to replace our reqwest client because that's the only way
        // to currently flush the cookie store. To achieve this we need to rebuild
        // and then destructure.
        let builder = self.builder.clone();
        let KanidmAsyncClient { mut client, .. } = builder.build_async()?;

        std::mem::swap(&mut self.client, &mut client);
        Ok(())
    }

    async fn perform_auth_post_request<R: Serialize, T: DeserializeOwned>(
        &mut self,
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

        // If we have a session header, set it now.
        let response = if let Some(sessionid) = &self.auth_session_id {
            response.header(KSESSIONID, sessionid)
        } else {
            response
        };

        let response = response.send().await.map_err(ClientError::Transport)?;

        // If we have a sessionid header in the response, get it now.

        let headers = response.headers();

        self.auth_session_id = headers
            .get(KSESSIONID)
            .map(|hv| hv.to_str().ok().map(|s| s.to_string()))
            .flatten();

        let opid = headers
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

    pub async fn auth_step_init(&mut self, ident: &str) -> Result<Set<AuthMech>, ClientError> {
        let auth_init = AuthRequest {
            step: AuthStep::Init(ident.to_string()),
        };

        let r: Result<AuthResponse, _> =
            self.perform_auth_post_request("/v1/auth", auth_init).await;
        r.map(|v| {
            debug!("Authentication Session ID -> {:?}", v.sessionid);
            // Stash the session ID header.
            v.state
        })
        .and_then(|state| match state {
            AuthState::Choose(mechs) => Ok(mechs),
            _ => Err(ClientError::AuthenticationFailed),
        })
        .map(|mechs| mechs.into_iter().collect())
    }

    pub async fn auth_step_begin(
        &mut self,
        mech: AuthMech,
    ) -> Result<Vec<AuthAllowed>, ClientError> {
        let auth_begin = AuthRequest {
            step: AuthStep::Begin(mech),
        };

        let r: Result<AuthResponse, _> =
            self.perform_auth_post_request("/v1/auth", auth_begin).await;
        r.map(|v| {
            debug!("Authentication Session ID -> {:?}", v.sessionid);
            v.state
        })
        .and_then(|state| match state {
            AuthState::Continue(allowed) => Ok(allowed),
            _ => Err(ClientError::AuthenticationFailed),
        })
        // For converting to a Set
        // .map(|allowed| allowed.into_iter().collect())
    }

    pub async fn auth_step_anonymous(&mut self) -> Result<AuthResponse, ClientError> {
        let auth_anon = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Anonymous),
        };
        let r: Result<AuthResponse, _> =
            self.perform_auth_post_request("/v1/auth", auth_anon).await;

        r.map(|ar| {
            if let AuthState::Success(token) = &ar.state {
                self.bearer_token = Some(token.clone());
            };
            ar
        })
    }

    pub async fn auth_step_password(
        &mut self,
        password: &str,
    ) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Password(password.to_string())),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        r.map(|ar| {
            if let AuthState::Success(token) = &ar.state {
                self.bearer_token = Some(token.clone());
            };
            ar
        })
    }

    pub async fn auth_step_totp(&mut self, totp: u32) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::TOTP(totp)),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        r.map(|ar| {
            if let AuthState::Success(token) = &ar.state {
                self.bearer_token = Some(token.clone());
            };
            ar
        })
    }

    pub async fn auth_step_webauthn_complete(
        &mut self,
        pkc: PublicKeyCredential,
    ) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Webauthn(pkc)),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        r.map(|ar| {
            if let AuthState::Success(token) = &ar.state {
                self.bearer_token = Some(token.clone());
            };
            ar
        })
    }

    pub async fn auth_anonymous(&mut self) -> Result<(), ClientError> {
        let mechs = match self.auth_step_init("anonymous").await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::Anonymous) {
            debug!("Anonymous mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let _state = match self.auth_step_begin(AuthMech::Anonymous).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let r = self.auth_step_anonymous().await?;

        match r.state {
            AuthState::Success(token) => {
                self.bearer_token = Some(token);
                Ok(())
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn auth_simple_password(
        &mut self,
        ident: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::Password) {
            debug!("Password mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let _state = match self.auth_step_begin(AuthMech::Password).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn auth_password_totp(
        &mut self,
        ident: &str,
        password: &str,
        totp: u32,
    ) -> Result<(), ClientError> {
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::PasswordMFA) {
            debug!("PasswordMFA mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let state = match self.auth_step_begin(AuthMech::PasswordMFA).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !state.contains(&AuthAllowed::TOTP) {
            debug!("TOTP step not offered.");
            return Err(ClientError::AuthenticationFailed);
        }

        let r = self.auth_step_totp(totp).await?;

        // Should need to continue.
        match r.state {
            AuthState::Continue(allowed) => {
                if !allowed.contains(&AuthAllowed::Password) {
                    debug!("Password step not offered.");
                    return Err(ClientError::AuthenticationFailed);
                }
            }
            _ => {
                debug!("Invalid AuthState presented.");
                return Err(ClientError::AuthenticationFailed);
            }
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn auth_webauthn_begin(
        &mut self,
        ident: &str,
    ) -> Result<RequestChallengeResponse, ClientError> {
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::Webauthn) {
            debug!("Webauthn mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let mut state = match self.auth_step_begin(AuthMech::Webauthn).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        // State is now a set of auth continues.
        match state.pop() {
            Some(AuthAllowed::Webauthn(r)) => Ok(r),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn auth_webauthn_complete(
        &mut self,
        pkc: PublicKeyCredential,
    ) -> Result<(), ClientError> {
        let r = self.auth_step_webauthn_complete(pkc).await?;
        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn whoami(&self) -> Result<Option<(Entry, UserAuthToken)>, ClientError> {
        let whoami_dest = [self.addr.as_str(), "/v1/self"].concat();
        // format!("{}/v1/self", self.addr);
        debug!("{:?}", whoami_dest);
        let response = self.client.get(whoami_dest.as_str());

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

    // Raw DB actions
    pub async fn search(&self, filter: Filter) -> Result<Vec<Entry>, ClientError> {
        let sr = SearchRequest { filter };
        let r: Result<SearchResponse, _> = self.perform_post_request("/v1/raw/search", sr).await;
        r.map(|v| v.entries)
    }

    pub async fn create(&self, entries: Vec<Entry>) -> Result<bool, ClientError> {
        let c = CreateRequest { entries };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/create", c).await;
        r.map(|_| true)
    }

    pub async fn modify(&self, filter: Filter, modlist: ModifyList) -> Result<bool, ClientError> {
        let mr = ModifyRequest { filter, modlist };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/modify", mr).await;
        r.map(|_| true)
    }

    pub async fn delete(&self, filter: Filter) -> Result<bool, ClientError> {
        let dr = DeleteRequest { filter };
        let r: Result<OperationResponse, _> = self.perform_post_request("/v1/raw/delete", dr).await;
        r.map(|_| true)
    }

    // === idm actions here ==

    // ===== GROUPS
    pub async fn idm_group_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/group").await
    }

    pub async fn idm_group_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/group/{}", id).as_str())
            .await
    }

    pub async fn idm_group_get_members(
        &self,
        id: &str,
    ) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(format!("/v1/group/{}/_attr/member", id).as_str())
            .await
    }

    pub async fn idm_group_create(&self, name: &str) -> Result<bool, ClientError> {
        let mut new_group = Entry {
            attrs: BTreeMap::new(),
        };
        new_group
            .attrs
            .insert("name".to_string(), vec![name.to_string()]);
        self.perform_post_request("/v1/group", new_group)
            .await
            .map(|_: OperationResponse| true)
    }

    pub async fn idm_group_set_members(
        &self,
        id: &str,
        members: &[&str],
    ) -> Result<bool, ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(format!("/v1/group/{}/_attr/member", id).as_str(), m)
            .await
    }

    pub async fn idm_group_add_members(
        &self,
        id: &str,
        members: &[&str],
    ) -> Result<bool, ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(["/v1/group/", id, "/_attr/member"].concat().as_str(), m)
            .await
    }

    /*
    pub fn idm_group_remove_member(&self, id: &str, member: &str) -> Result<(), ClientError> {
        unimplemented!();
    }
    */

    pub async fn idm_group_purge_members(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(format!("/v1/group/{}/_attr/member", id).as_str())
            .await
    }

    pub async fn idm_group_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
    ) -> Result<bool, ClientError> {
        let gx = GroupUnixExtend { gidnumber };
        self.perform_post_request(format!("/v1/group/{}/_unix", id).as_str(), gx)
            .await
    }

    pub async fn idm_group_unix_token_get(&self, id: &str) -> Result<UnixGroupToken, ClientError> {
        // Format doesn't work in async
        // format!("/v1/account/{}/_unix/_token", id).as_str()
        self.perform_get_request(["/v1/group/", id, "/_unix/_token"].concat().as_str())
            .await
    }

    pub async fn idm_group_delete(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(["/v1/group/", id].concat().as_str())
            .await
    }

    // ==== ACCOUNTS
    pub async fn idm_account_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/account").await
    }

    pub async fn idm_account_create(&self, name: &str, dn: &str) -> Result<bool, ClientError> {
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
            .await
            .map(|_: OperationResponse| true)
    }

    pub async fn idm_account_set_password(&self, cleartext: String) -> Result<bool, ClientError> {
        let s = SingleStringRequest { value: cleartext };

        let r: Result<OperationResponse, _> = self
            .perform_post_request("/v1/self/_credential/primary/set_password", s)
            .await;
        r.map(|_| true)
    }

    pub async fn idm_account_set_displayname(
        &self,
        id: &str,
        dn: &str,
    ) -> Result<bool, ClientError> {
        self.idm_account_set_attr(id, "displayname", &[dn]).await
    }

    pub async fn idm_account_unix_token_get(&self, id: &str) -> Result<UnixUserToken, ClientError> {
        // Format doesn't work in async
        // format!("/v1/account/{}/_unix/_token", id).as_str()
        self.perform_get_request(["/v1/account/", id, "/_unix/_token"].concat().as_str())
            .await
    }

    pub async fn idm_account_delete(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(["/v1/account/", id].concat().as_str())
            .await
    }

    pub async fn idm_account_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}", id).as_str())
            .await
    }

    pub async fn idm_account_set_attr(
        &self,
        id: &str,
        attr: &str,
        values: &[&str],
    ) -> Result<bool, ClientError> {
        let m: Vec<_> = values.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(format!("/v1/account/{}/_attr/{}", id, attr).as_str(), m)
            .await
    }

    pub async fn idm_account_get_attr(
        &self,
        id: &str,
        attr: &str,
    ) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_attr/{}", id, attr).as_str())
            .await
    }

    pub async fn idm_account_purge_attr(&self, id: &str, attr: &str) -> Result<bool, ClientError> {
        self.perform_delete_request(format!("/v1/account/{}/_attr/{}", id, attr).as_str())
            .await
    }

    pub async fn idm_account_primary_credential_set_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<SetCredentialResponse, ClientError> {
        let r = SetCredentialRequest::Password(pw.to_string());
        self.perform_put_request(
            format!("/v1/account/{}/_credential/primary", id).as_str(),
            r,
        )
        .await
    }

    pub async fn idm_account_primary_credential_import_password(
        &self,
        id: &str,
        pw: &str,
    ) -> Result<bool, ClientError> {
        self.perform_put_request(
            format!("/v1/account/{}/_attr/password_import", id).as_str(),
            vec![pw.to_string()],
        )
        .await
    }

    pub async fn idm_account_primary_credential_set_generated(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        let r = SetCredentialRequest::GeneratePassword;
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::Token(p)) => Ok(p),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    // Reg intent for totp
    pub async fn idm_account_primary_credential_generate_totp(
        &self,
        id: &str,
        label: &str,
    ) -> Result<(Uuid, TOTPSecret), ClientError> {
        let r = SetCredentialRequest::TOTPGenerate(label.to_string());
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::TOTPCheck(u, s)) => Ok((u, s)),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    // Verify the totp
    pub async fn idm_account_primary_credential_verify_totp(
        &self,
        id: &str,
        otp: u32,
        session: Uuid,
    ) -> Result<bool, ClientError> {
        let r = SetCredentialRequest::TOTPVerify(session, otp);
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::Success) => Ok(true),
            Ok(SetCredentialResponse::TOTPCheck(u, s)) => Err(ClientError::TOTPVerifyFailed(u, s)),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    pub async fn idm_account_primary_credential_remove_totp(
        &self,
        id: &str,
    ) -> Result<bool, ClientError> {
        let r = SetCredentialRequest::TOTPRemove;
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::Success) => Ok(true),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    pub async fn idm_account_primary_credential_register_webauthn(
        &self,
        id: &str,
        label: &str,
    ) -> Result<(Uuid, CreationChallengeResponse), ClientError> {
        let r = SetCredentialRequest::WebauthnBegin(label.to_string());
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::WebauthnCreateChallenge(u, s)) => Ok((u, s)),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    pub async fn idm_account_primary_credential_complete_webuthn_registration(
        &self,
        id: &str,
        rego: RegisterPublicKeyCredential,
        session: Uuid,
    ) -> Result<(), ClientError> {
        let r = SetCredentialRequest::WebauthnRegister(session, rego);
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::Success) => Ok(()),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    pub async fn idm_account_primary_credential_remove_webauthn(
        &self,
        id: &str,
        label: &str,
    ) -> Result<bool, ClientError> {
        let r = SetCredentialRequest::WebauthnRemove(label.to_string());
        let res: Result<SetCredentialResponse, ClientError> = self
            .perform_put_request(
                format!("/v1/account/{}/_credential/primary", id).as_str(),
                r,
            )
            .await;
        match res {
            Ok(SetCredentialResponse::Success) => Ok(true),
            Ok(_) => Err(ClientError::EmptyResponse),
            Err(e) => Err(e),
        }
    }

    pub async fn idm_account_get_credential_status(
        &self,
        id: &str,
    ) -> Result<CredentialStatus, ClientError> {
        let res: Result<CredentialStatus, ClientError> = self
            .perform_get_request(format!("/v1/account/{}/_credential/_status", id).as_str())
            .await;
        res.and_then(|cs| {
            if cs.creds.is_empty() {
                Err(ClientError::EmptyResponse)
            } else {
                Ok(cs)
            }
        })
    }

    pub async fn idm_account_radius_credential_get(
        &self,
        id: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_radius", id).as_str())
            .await
    }

    pub async fn idm_account_radius_credential_regenerate(
        &self,
        id: &str,
    ) -> Result<String, ClientError> {
        self.perform_post_request(format!("/v1/account/{}/_radius", id).as_str(), ())
            .await
    }

    pub async fn idm_account_radius_credential_delete(
        &self,
        id: &str,
    ) -> Result<bool, ClientError> {
        self.perform_delete_request(format!("/v1/account/{}/_radius", id).as_str())
            .await
    }

    pub async fn idm_account_radius_token_get(
        &self,
        id: &str,
    ) -> Result<RadiusAuthToken, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_radius/_token", id).as_str())
            .await
    }

    pub async fn idm_account_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
        shell: Option<&str>,
    ) -> Result<bool, ClientError> {
        let ux = AccountUnixExtend {
            shell: shell.map(|s| s.to_string()),
            gidnumber,
        };
        self.perform_post_request(format!("/v1/account/{}/_unix", id).as_str(), ux)
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

    pub async fn idm_account_get_ssh_pubkeys(&self, id: &str) -> Result<Vec<String>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_ssh_pubkeys", id).as_str())
            .await
    }

    pub async fn idm_account_post_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
        pubkey: &str,
    ) -> Result<bool, ClientError> {
        let sk = (tag.to_string(), pubkey.to_string());
        self.perform_post_request(format!("/v1/account/{}/_ssh_pubkeys", id).as_str(), sk)
            .await
    }

    pub async fn idm_account_person_extend(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_post_request(format!("/v1/account/{}/_person/_extend", id).as_str(), ())
            .await
    }

    pub async fn idm_account_get_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/account/{}/_ssh_pubkeys/{}", id, tag).as_str())
            .await
    }

    pub async fn idm_account_delete_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<bool, ClientError> {
        self.perform_delete_request(format!("/v1/account/{}/_ssh_pubkeys/{}", id, tag).as_str())
            .await
    }

    // ==== domain_info (aka domain)
    pub async fn idm_domain_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/domain").await
    }

    pub async fn idm_domain_get(&self, id: &str) -> Result<Entry, ClientError> {
        self.perform_get_request(format!("/v1/domain/{}", id).as_str())
            .await
    }

    // pub fn idm_domain_get_attr
    pub async fn idm_domain_get_ssid(&self, id: &str) -> Result<String, ClientError> {
        self.perform_get_request(format!("/v1/domain/{}/_attr/domain_ssid", id).as_str())
            .await
            .and_then(|mut r: Vec<String>|
                // Get the first result
                r.pop()
                .ok_or(
                    ClientError::EmptyResponse
                ))
    }

    // pub fn idm_domain_put_attr
    pub async fn idm_domain_set_ssid(&self, id: &str, ssid: &str) -> Result<bool, ClientError> {
        self.perform_put_request(
            format!("/v1/domain/{}/_attr/domain_ssid", id).as_str(),
            vec![ssid.to_string()],
        )
        .await
    }

    // ==== schema
    pub async fn idm_schema_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema").await
    }

    pub async fn idm_schema_attributetype_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema/attributetype").await
    }

    pub async fn idm_schema_attributetype_get(
        &self,
        id: &str,
    ) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/schema/attributetype/{}", id).as_str())
            .await
    }

    pub async fn idm_schema_classtype_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema/classtype").await
    }

    pub async fn idm_schema_classtype_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/schema/classtype/{}", id).as_str())
            .await
    }

    // ==== recycle bin
    pub async fn recycle_bin_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/recycle_bin").await
    }

    pub async fn recycle_bin_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/recycle_bin/{}", id).as_str())
            .await
    }

    pub async fn recycle_bin_revive(&self, id: &str) -> Result<bool, ClientError> {
        self.perform_post_request(format!("/v1/recycle_bin/{}/_revive", id).as_str(), ())
            .await
    }
}
