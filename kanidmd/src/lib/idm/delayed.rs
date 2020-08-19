use uuid::Uuid;

pub(crate) enum DelayedAction {
    PwUpgrade(PasswordUpgrade),
    UnixPwUpgrade(UnixPasswordUpgrade),
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
