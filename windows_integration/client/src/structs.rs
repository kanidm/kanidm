use windows::Win32::Foundation::{LUID};

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
