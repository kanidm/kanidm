use crate::unix_config::{HomeAttr, UidAttr};

pub const DEFAULT_CONFIG_PATH: &str = env!("KANIDM_RESOLVER_CONFIG_PATH");
pub const DEFAULT_SOCK_PATH: &str = "/var/run/kanidm-unixd/sock";
pub const DEFAULT_TASK_SOCK_PATH: &str = "/var/run/kanidm-unixd/task_sock";
pub const DEFAULT_PERSISTENT_DB_PATH: &str = "/var/lib/kanidm-unixd/kanidm.db";
pub const DEFAULT_CACHE_DB_PATH: &str = "/var/cache/kanidm-unixd/kanidm.cache.db";
pub const DEFAULT_CONN_TIMEOUT: u64 = 2;
pub const DEFAULT_CACHE_TIMEOUT: u64 = 120;
// When there is 30 seconds of validity remaining, perform an async refresh.
pub const DEFAULT_CACHE_ASYNC_REFRESH: u64 = 30;
pub const DEFAULT_CACHE_TIMEOUT_JITTER_MS: u64 = 10_000;
pub const DEFAULT_SHELL: &str = env!("KANIDM_RESOLVER_UNIX_SHELL_PATH");
pub const DEFAULT_HOME_PREFIX: &str = "/home/";
pub const DEFAULT_HOME_ATTR: HomeAttr = HomeAttr::Uuid;
pub const DEFAULT_HOME_ALIAS: Option<HomeAttr> = Some(HomeAttr::Spn);
pub const DEFAULT_USE_ETC_SKEL: bool = false;
pub const DEFAULT_UID_ATTR_MAP: UidAttr = UidAttr::Spn;
pub const DEFAULT_GID_ATTR_MAP: UidAttr = UidAttr::Spn;
pub const DEFAULT_SELINUX: bool = true;
pub const DEFAULT_TPM_TCTI_NAME: &str = "device:/dev/tpmrm0";
pub const DEFAULT_HSM_PIN_PATH: &str = "/var/lib/kanidm-unixd/hsm-pin";
pub const DEFAULT_KANIDM_SERVICE_ACCOUNT_TOKEN_PATH: &str =
    env!("KANIDM_RESOLVER_SERVICE_ACCOUNT_TOKEN_PATH");

#[cfg(all(target_family = "unix", not(target_os = "freebsd")))]
pub const DEFAULT_SHELL_SEARCH_PATHS: &[&str] = &["/bin"];

#[cfg(all(target_family = "unix", target_os = "freebsd"))]
pub const DEFAULT_SHELL_SEARCH_PATHS: &[&str] = &["/bin", "/usr/local/bin"];

// The minimum size of a buffer for the unix stream codec
pub const CODEC_MIMIMUM_BYTESMUT_ALLOCATION: usize = 64;
// If the codec buffer exceeds this limit, then we swap the buffer
// with a fresh one to prevent memory explosions.
pub const CODEC_BYTESMUT_ALLOCATION_LIMIT: usize = 1024 * 1024;

#[cfg(all(target_family = "unix", not(target_os = "freebsd")))]
pub const SYSTEM_SHADOW_PATH: &str = "/etc/shadow";

#[cfg(all(target_family = "unix", target_os = "freebsd"))]
pub const SYSTEM_SHADOW_PATH: &str = "/etc/master.passwd";

pub const SYSTEM_PASSWD_PATH: &str = "/etc/passwd";
pub const SYSTEM_GROUP_PATH: &str = "/etc/group";
