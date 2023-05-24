use kanidm_proto::v1::UnixUserToken;
use windows::Win32::Foundation::{LUID, UNICODE_STRING};

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
    pub low_part: u32,
    pub high_part: i32,
}

impl From<LUID> for LogonId {
    fn from(luid: LUID) -> Self {
        LogonId {
            low_part: luid.LowPart,
            high_part: luid.HighPart,
        }
    }
}
