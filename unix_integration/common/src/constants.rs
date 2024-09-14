use crate::unix_config::{HomeAttr, UidAttr};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/kanidm/unixd";
pub const DEFAULT_SOCK_PATH: &str = "/var/run/kanidm-unixd/sock";
pub const DEFAULT_TASK_SOCK_PATH: &str = "/var/run/kanidm-unixd/task_sock";
pub const DEFAULT_CACHE_DB_PATH: &str = "/var/cache/kanidm-unixd/kanidm.cache.db";
pub const DEFAULT_CONN_TIMEOUT: u64 = 2;
pub const DEFAULT_CACHE_TIMEOUT: u64 = 15;
pub const DEFAULT_SHELL: &str = env!("KANIDM_DEFAULT_UNIX_SHELL_PATH");
pub const DEFAULT_HOME_PREFIX: &str = "/home/";
pub const DEFAULT_HOME_ATTR: HomeAttr = HomeAttr::Uuid;
pub const DEFAULT_HOME_ALIAS: Option<HomeAttr> = Some(HomeAttr::Spn);
pub const DEFAULT_USE_ETC_SKEL: bool = false;
pub const DEFAULT_UID_ATTR_MAP: UidAttr = UidAttr::Spn;
pub const DEFAULT_GID_ATTR_MAP: UidAttr = UidAttr::Spn;
pub const DEFAULT_SELINUX: bool = true;
pub const DEFAULT_TPM_TCTI_NAME: &str = "device:/dev/tpmrm0";
pub const DEFAULT_HSM_PIN_PATH: &str = "/var/lib/kanidm-unixd/hsm-pin";
