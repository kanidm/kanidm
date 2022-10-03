use uuid::Uuid;
use webauthn_rs::prelude::AuthenticationResult;

pub enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
    WebauthnCounterIncrement(WebauthnCounterIncrement),
    BackupCodeRemoval(BackupCodeRemoval),
    Oauth2ConsentGrant(Oauth2ConsentGrant),
}

pub struct PasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

pub struct UnixPasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

pub struct WebauthnCounterIncrement {
    pub target_uuid: Uuid,
    pub auth_result: AuthenticationResult,
}

pub struct BackupCodeRemoval {
    pub target_uuid: Uuid,
    pub code_to_remove: String,
}

pub struct Oauth2ConsentGrant {
    pub target_uuid: Uuid,
    pub oauth2_rs_uuid: Uuid,
    pub scopes: Vec<String>,
}
