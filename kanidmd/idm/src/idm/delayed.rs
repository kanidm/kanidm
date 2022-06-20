use uuid::Uuid;
use webauthn_rs::proto::{Counter, CredentialID};

pub(crate) enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
    WebauthnCounterIncrement(WebauthnCounterIncrement),
    BackupCodeRemoval(BackupCodeRemoval),
    Oauth2ConsentGrant(Oauth2ConsentGrant),
}

pub(crate) struct PasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

pub(crate) struct UnixPasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
}

pub(crate) struct WebauthnCounterIncrement {
    pub target_uuid: Uuid,
    pub counter: Counter,
    pub cid: CredentialID,
}

pub(crate) struct BackupCodeRemoval {
    pub target_uuid: Uuid,
    pub code_to_remove: String,
}

pub(crate) struct Oauth2ConsentGrant {
    pub target_uuid: Uuid,
    pub oauth2_rs_uuid: Uuid,
    pub scopes: Vec<String>,
}
