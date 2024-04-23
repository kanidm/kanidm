// Re-export as needed

pub mod acp;
pub mod entries;
pub mod groups;
mod key_providers;
pub mod schema;
pub mod system_config;
pub mod uuids;
pub mod values;

pub use self::acp::*;
pub use self::entries::*;
pub use self::groups::*;
pub use self::key_providers::*;
pub use self::schema::*;
pub use self::system_config::*;
pub use self::uuids::*;
pub use self::values::*;

use std::time::Duration;

// This value no longer requires incrementing during releases. It only
// serves as a "once off" marker so that we know when the initial db
// index is performed on first-run.
pub const SYSTEM_INDEX_VERSION: i64 = 31;

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

/// Domain level 0 - this indicates that this instance
/// is a new install and has never had a domain level
/// previously.
pub const DOMAIN_LEVEL_0: DomainVersion = 0;

/// Deprcated as of 1.2.0
pub const DOMAIN_LEVEL_1: DomainVersion = 1;
/// Deprcated as of 1.2.0
pub const DOMAIN_LEVEL_2: DomainVersion = 2;
/// Deprcated as of 1.2.0
pub const DOMAIN_LEVEL_3: DomainVersion = 3;
/// Deprcated as of 1.2.0
pub const DOMAIN_LEVEL_4: DomainVersion = 4;
/// Deprcated as of 1.3.0
pub const DOMAIN_LEVEL_5: DomainVersion = 5;

/// Domain Level introduced with 1.2.0.
/// Deprcated as of 1.4.0
pub const DOMAIN_LEVEL_6: DomainVersion = 6;

/// Domain Level introduced with 1.3.0.
/// Deprcated as of 1.5.0
pub const DOMAIN_LEVEL_7: DomainVersion = 7;

// The minimum level that we can re-migrate from
pub const DOMAIN_MIN_REMIGRATION_LEVEL: DomainVersion = DOMAIN_LEVEL_2;
// The minimum supported domain functional level
pub const DOMAIN_MIN_LEVEL: DomainVersion = DOMAIN_TGT_LEVEL;
// The previous releases domain functional level
pub const DOMAIN_PREVIOUS_TGT_LEVEL: DomainVersion = DOMAIN_LEVEL_5;
// The target supported domain functional level
pub const DOMAIN_TGT_LEVEL: DomainVersion = DOMAIN_LEVEL_6;
// The maximum supported domain functional level
pub const DOMAIN_MAX_LEVEL: DomainVersion = DOMAIN_LEVEL_6;
// The maximum supported domain functional level
pub const DOMAIN_NEXT_LEVEL: DomainVersion = DOMAIN_LEVEL_7;

// On test builds define to 60 seconds
#[cfg(test)]
pub const PURGE_FREQUENCY: u64 = 60;
// For production 10 minutes.
#[cfg(not(test))]
pub const PURGE_FREQUENCY: u64 = 600;

#[cfg(test)]
/// In test, we limit the changelog to 10 minutes.
pub const CHANGELOG_MAX_AGE: u64 = 600;
#[cfg(not(test))]
/// A replica may be up to 7 days out of sync before being denied updates.
pub const CHANGELOG_MAX_AGE: u64 = 7 * 86400;

#[cfg(test)]
/// In test, we limit the recyclebin to 5 minutes.
pub const RECYCLEBIN_MAX_AGE: u64 = 300;
#[cfg(not(test))]
/// In production we allow 1 week
pub const RECYCLEBIN_MAX_AGE: u64 = 7 * 86400;

// 5 minute auth session window.
pub const AUTH_SESSION_TIMEOUT: u64 = 300;
// 5 minute mfa reg window
pub const MFAREG_SESSION_TIMEOUT: u64 = 300;
pub const PW_MIN_LENGTH: u32 = 10;

// Maximum - Sessions have no upper bound.
pub const MAXIMUM_AUTH_SESSION_EXPIRY: u32 = u32::MAX;
// Default - sessions last for 1 day
pub const DEFAULT_AUTH_SESSION_EXPIRY: u32 = 86400;
pub const DEFAULT_AUTH_SESSION_LIMITED_EXPIRY: u32 = 3600;
// Maximum - privileges last for 1 hour.
pub const MAXIMUM_AUTH_PRIVILEGE_EXPIRY: u32 = 3600;
// Default - privileges last for 10 minutes.
pub const DEFAULT_AUTH_PRIVILEGE_EXPIRY: u32 = 600;
// Default - oauth refresh tokens last for 16 hours.
pub const OAUTH_REFRESH_TOKEN_EXPIRY: u64 = 3600 * 8;

// The time that a token can be used before session
// status is enforced. This needs to be longer than
// replication delay/cycle.
pub const GRACE_WINDOW: Duration = Duration::from_secs(300);

/// How long access tokens should last. This is NOT the length
/// of the refresh token, which is bound to the issuing session.
pub const OAUTH2_ACCESS_TOKEN_EXPIRY: u32 = 15 * 60;

/// The amount of time a suppliers clock can be "ahead" before
/// we warn about possible clock synchronisation issues.
pub const REPL_SUPPLIER_ADVANCE_WINDOW: Duration = Duration::from_secs(600);

/// The default number of entries that a user may retrieve in a search
pub const DEFAULT_LIMIT_SEARCH_MAX_RESULTS: u64 = 1024;
/// The default number of entries than an api token may retrieve in a search;
pub const DEFAULT_LIMIT_API_SEARCH_MAX_RESULTS: u64 = u64::MAX >> 1;
/// the default number of entries that may be examined in a partially indexed
/// query.
pub const DEFAULT_LIMIT_SEARCH_MAX_FILTER_TEST: u64 = 2048;
/// the default number of entries that may be examined in a partially indexed
/// query by an api token.
pub const DEFAULT_LIMIT_API_SEARCH_MAX_FILTER_TEST: u64 = 16384;
/// The maximum number of items in a filter, regardless of nesting level.
pub const DEFAULT_LIMIT_FILTER_MAX_ELEMENTS: u64 = 32;

/// The maximum amount of recursion allowed in a filter.
pub const DEFAULT_LIMIT_FILTER_DEPTH_MAX: u64 = 12;

/// The maximum number of sessions allowed on a single entry.
pub(crate) const SESSION_MAXIMUM: usize = 48;
