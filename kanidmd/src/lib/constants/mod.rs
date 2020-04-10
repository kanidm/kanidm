// Re-export as needed

pub mod acp;
pub mod entries;
pub mod schema;
pub mod system_config;
pub mod uuids;

pub use crate::constants::acp::*;
pub use crate::constants::entries::*;
pub use crate::constants::schema::*;
pub use crate::constants::system_config::*;
pub use crate::constants::uuids::*;

// Increment this as we add new schema types and values!!!
pub static SYSTEM_INDEX_VERSION: i64 = 6;
// On test builds, define to 60 seconds
#[cfg(test)]
pub static PURGE_FREQUENCY: u64 = 60;
// For production, 10 minutes.
#[cfg(not(test))]
pub static PURGE_FREQUENCY: u64 = 600;

#[cfg(test)]
/// In test, we limit the changelog to 10 minutes.
pub static CHANGELOG_MAX_AGE: u64 = 600;
#[cfg(not(test))]
/// A replica may be less than 1 day out of sync and catch up.
pub static CHANGELOG_MAX_AGE: u64 = 86400;

#[cfg(test)]
/// In test, we limit the recyclebin to 5 minutes.
pub static RECYCLEBIN_MAX_AGE: u64 = 300;
#[cfg(not(test))]
/// In production we allow 1 week
pub static RECYCLEBIN_MAX_AGE: u64 = 604800;

// 5 minute auth session window.
pub static AUTH_SESSION_TIMEOUT: u64 = 300;
// 5 minute mfa reg window
pub static MFAREG_SESSION_TIMEOUT: u64 = 300;
pub static PW_MIN_LENGTH: usize = 10;
