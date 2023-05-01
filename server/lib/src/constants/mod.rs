// Re-export as needed

pub mod acp;
pub mod entries;
pub mod schema;
pub mod system_config;
pub mod uuids;
pub mod values;

pub use crate::constants::acp::*;
pub use crate::constants::entries::*;
pub use crate::constants::schema::*;
pub use crate::constants::system_config::*;
pub use crate::constants::uuids::*;
pub use crate::constants::values::*;

use std::time::Duration;

// Increment this as we add new schema types and values!!!
pub const SYSTEM_INDEX_VERSION: i64 = 29;

/*
 * domain functional levels
 *
 * The idea here is to allow topology wide upgrades to be performed. We have to
 * assume that across multiple kanidm instances there may be cases where we have version
 * N and version N minus 1 as upgrades are rolled out.
 *
 * Imagine we set up a new cluster. Machine A and B both have level 1 support.
 * We upgrade machine A. It has support up to level 2, but machine B does not.
 * So the overall functional level is level 1. Then we upgrade B, which supports
 * up to level 2. We still don't do the upgrade! The topology is still level 1
 * unless an admin at this point *intervenes* and forces the update. OR what
 * happens we we update machine A again and it now supports up to level 3, with
 * a target level of 2. So we update machine A now to level 2, and that can
 * still replicate to machine B since it also supports level 2.
 *
 * effectively it means that "some features" may be a "release behind" for users
 * who don't muck with the levels, but it means that we can do mixed version
 * upgrades.
 */
pub type DomainVersion = u32;

pub const DOMAIN_LEVEL_1: DomainVersion = 1;
// The minimum supported domain functional level
pub const DOMAIN_MIN_LEVEL: DomainVersion = DOMAIN_LEVEL_1;
// The target supported domain functional level
pub const DOMAIN_TGT_LEVEL: DomainVersion = DOMAIN_LEVEL_1;
// The maximum supported domain functional level
pub const DOMAIN_MAX_LEVEL: DomainVersion = DOMAIN_LEVEL_1;

// On test builds, define to 60 seconds
#[cfg(test)]
pub const PURGE_FREQUENCY: u64 = 60;
// For production, 10 minutes.
#[cfg(not(test))]
pub const PURGE_FREQUENCY: u64 = 600;

#[cfg(test)]
/// In test, we limit the changelog to 10 minutes.
pub const CHANGELOG_MAX_AGE: u64 = 600;
#[cfg(not(test))]
/// A replica may be less than 1 day out of sync and catch up.
pub const CHANGELOG_MAX_AGE: u64 = 86400;

#[cfg(test)]
/// In test, we limit the recyclebin to 5 minutes.
pub const RECYCLEBIN_MAX_AGE: u64 = 300;
#[cfg(not(test))]
/// In production we allow 1 week
pub const RECYCLEBIN_MAX_AGE: u64 = 604_800;

// 5 minute auth session window.
pub const AUTH_SESSION_TIMEOUT: u64 = 300;
// 5 minute mfa reg window
pub const MFAREG_SESSION_TIMEOUT: u64 = 300;
pub const PW_MIN_LENGTH: usize = 10;

// Default - sessions last for 1 hour.
pub const AUTH_SESSION_EXPIRY: u64 = 3600;
// Default - privileges last for 10 minutes.
pub const AUTH_PRIVILEGE_EXPIRY: u64 = 600;
// Default - oauth refresh tokens last for 16 hours.
pub const OAUTH_REFRESH_TOKEN_EXPIRY: u64 = 3600 * 8;

// The time that a token can be used before session
// status is enforced. This needs to be longer than
// replication delay/cycle.
pub const GRACE_WINDOW: Duration = Duration::from_secs(300);

/// How long access tokens should last. This is NOT the length
/// of the refresh token, which is bound to the issuing session.
pub const OAUTH2_ACCESS_TOKEN_EXPIRY: u32 = 15 * 60;
