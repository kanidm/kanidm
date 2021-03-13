use crate::unix_config::{HomeAttr, UidAttr};

pub const DEFAULT_SOCK_PATH: &str = "/var/run/kanidm-unixd/sock";
pub const DEFAULT_TASK_SOCK_PATH: &str = "/var/run/kanidm-unixd/task_sock";
pub const DEFAULT_DB_PATH: &str = "/var/cache/kanidm-unixd/kanidm.cache.db";
pub const DEFAULT_CONN_TIMEOUT: u64 = 2;
pub const DEFAULT_CACHE_TIMEOUT: u64 = 15;
pub const DEFAULT_SHELL: &str = "/bin/bash";
pub const DEFAULT_HOME_PREFIX: &str = "/home/";
pub const DEFAULT_HOME_ATTR: HomeAttr = HomeAttr::Uuid;
pub const DEFAULT_HOME_ALIAS: Option<HomeAttr> = Some(HomeAttr::Spn);
pub const DEFAULT_UID_ATTR_MAP: UidAttr = UidAttr::Spn;
pub const DEFAULT_GID_ATTR_MAP: UidAttr = UidAttr::Spn;
