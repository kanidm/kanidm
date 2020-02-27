use crate::pam::constants::{
    PamItemType, PAM_AUTHTOK, PAM_OLDAUTHTOK, PAM_RHOST, PAM_RUSER, PAM_SERVICE, PAM_TTY, PAM_USER,
    PAM_USER_PROMPT,
};
pub use crate::pam::conv::PamConv;
use crate::pam::module::PamItem;

pub struct PamService {}

impl PamItem for PamService {
    fn item_type() -> PamItemType {
        PAM_SERVICE
    }
}

pub struct PamUser {}

impl PamItem for PamUser {
    fn item_type() -> PamItemType {
        PAM_USER
    }
}

pub struct PamUserPrompt {}

impl PamItem for PamUserPrompt {
    fn item_type() -> PamItemType {
        PAM_USER_PROMPT
    }
}

pub struct PamTty {}

impl PamItem for PamTty {
    fn item_type() -> PamItemType {
        PAM_TTY
    }
}

pub struct PamRUser {}

impl PamItem for PamRUser {
    fn item_type() -> PamItemType {
        PAM_RUSER
    }
}

pub struct PamRHost {}

impl PamItem for PamRHost {
    fn item_type() -> PamItemType {
        PAM_RHOST
    }
}

pub struct PamAuthTok {}

impl PamItem for PamAuthTok {
    fn item_type() -> PamItemType {
        PAM_AUTHTOK
    }
}

pub struct PamOldAuthTok {}

impl PamItem for PamOldAuthTok {
    fn item_type() -> PamItemType {
        PAM_OLDAUTHTOK
    }
}
