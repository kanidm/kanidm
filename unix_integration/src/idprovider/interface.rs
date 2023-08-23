use crate::unix_proto::{PamAuthRequest, PamAuthResponse};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors that the IdProvider may return. These drive the resolver state machine
/// and should be carefully selected to match your expected errors.
#[derive(Debug)]
pub enum IdpError {
    /// An error occurred in the underlying communication to the Idp. A timeout or
    /// or other communication issue exists. The resolver will take this provider
    /// offline.
    Transport,
    /// The provider is online but the provider module is not current authorised with
    /// the idp. After returning this error the operation will be retried after a
    /// successful authentication.
    ProviderUnauthorised,
    /// The provider made an invalid request to the idp, and the result is not able to
    /// be used by the resolver.
    BadRequest,
    /// The idp has indicated that the requested resource does not exist and should
    /// be considered deleted, removed, or not present.
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Id {
    Name(String),
    Gid(u32),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupToken {
    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    pub gidnumber: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserToken {
    pub name: String,
    pub spn: String,
    pub uuid: Uuid,
    pub gidnumber: u32,
    pub displayname: String,
    pub shell: Option<String>,
    pub groups: Vec<GroupToken>,
    // Could there be a better type here?
    pub sshkeys: Vec<String>,
    // Defaults to false.
    pub valid: bool,
}

#[derive(Debug)]
pub enum AuthSession {
    InProgress {
        account_id: String,
        id: Id,
        token: Option<UserToken>,
        online_at_init: bool,
    },
    Success,
    Denied,
    Unknown,
}

impl AuthSession {
    pub fn next_credential(&self) -> PamAuthResponse {
        todo!();
    }
}

pub enum AuthCacheAction {
    None,
    PasswordHashUpdate,
}

#[async_trait]
pub trait IdProvider {
    async fn provider_authenticate(&self) -> Result<(), IdpError>;

    async fn unix_user_get(
        &self,
        id: &Id,
        old_token: Option<UserToken>,
    ) -> Result<UserToken, IdpError>;

    async fn unix_user_online_auth_init(
        &self,
        _id: &Id,
        _token: Option<UserToken>,
    ) -> Result<AuthSession, IdpError> {
        Ok(AuthSession::Unknown)
    }

    async fn unix_user_offline_auth_init(
        &self,
        _id: &Id,
        _token: Option<UserToken>,
    ) -> Result<AuthSession, IdpError> {
        Ok(AuthSession::Unknown)
    }

    async fn unix_user_online_auth_step(
        &self,
        _auth_session: &mut AuthSession,
        _pam_next_req: PamAuthRequest,
    ) -> Result<AuthCacheAction, IdpError> {
        Ok((AuthSession::Unknown, AuthCacheAction::None))
    }

    async fn unix_user_offline_auth_step(
        &self,
        _auth_session: &mut AuthSession,
        _pam_next_req: PamAuthRequest,
    ) -> Result<(), IdpError> {
        Ok(AuthSession::Unknown)
    }

    async fn unix_group_get(&self, id: &Id) -> Result<GroupToken, IdpError>;
}
