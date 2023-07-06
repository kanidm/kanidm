use crate::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::AuthenticationResult;

use std::fmt;

#[derive(Debug)]
pub enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
    WebauthnCounterIncrement(WebauthnCounterIncrement),
    BackupCodeRemoval(BackupCodeRemoval),
    AuthSessionRecord(AuthSessionRecord),
}

pub struct PasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

impl fmt::Debug for PasswordUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordUpgrade")
            .field("target_uuid", &self.target_uuid)
            .finish()
    }
}

pub struct UnixPasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

impl fmt::Debug for UnixPasswordUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixPasswordUpgrade")
            .field("target_uuid", &self.target_uuid)
            .finish()
    }
}

#[derive(Debug)]
pub struct WebauthnCounterIncrement {
    pub target_uuid: Uuid,
    pub auth_result: AuthenticationResult,
}

#[derive(Debug)]
pub struct BackupCodeRemoval {
    pub target_uuid: Uuid,
    pub code_to_remove: String,
}

#[derive(Debug)]
pub struct AuthSessionRecord {
    pub target_uuid: Uuid,
    pub session_id: Uuid,
    pub cred_id: Uuid,
    pub label: String,
    pub expiry: Option<OffsetDateTime>,
    pub issued_at: OffsetDateTime,
    pub issued_by: IdentityId,
    pub scope: SessionScope,
}
