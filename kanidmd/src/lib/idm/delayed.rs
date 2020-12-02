use uuid::Uuid;
use webauthn_rs::proto::{Counter, CredentialID};

pub(crate) enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
    WebauthnCounterIncrement(WebauthnCounterIncrement),
}

pub(crate) struct PasswordUpgrade {
    pub target_uuid: Uuid,
    pub existing_password: String,
    pub appid: Option<String>,
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
