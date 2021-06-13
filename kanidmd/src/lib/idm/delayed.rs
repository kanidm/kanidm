use uuid::Uuid;
use webauthn_rs::proto::{Counter, CredentialID};

use crate::credential::BackupCodes;

pub(crate) enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
    WebauthnCounterIncrement(WebauthnCounterIncrement),
    BackupCodeRemoval(BackupCodeRemoval),
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
    pub updated_codes: BackupCodes,
}
