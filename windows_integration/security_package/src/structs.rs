use kanidm_proto::v1::UnixUserToken;
use windows::Win32::Foundation::{UNICODE_STRING, LUID};

// * Logon User
pub struct AuthInfo {
    pub username: UNICODE_STRING,
    pub password: UNICODE_STRING,
}

pub struct ProfileBuffer {
    pub token: UnixUserToken,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct LogonId {
    pub LowPart: u32,
    pub HighPart: i32,
}

impl From<LUID> for LogonId {
    fn from(luid: LUID) -> Self {
        LogonId { LowPart: luid.LowPart, HighPart: luid.HighPart }
    }
}