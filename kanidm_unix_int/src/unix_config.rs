use crate::constants::{
    DEFAULT_CACHE_TIMEOUT, DEFAULT_CONN_TIMEOUT, DEFAULT_DB_PATH, DEFAULT_GID_ATTR_MAP,
    DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX, DEFAULT_SHELL, DEFAULT_SOCK_PATH,
    DEFAULT_TASK_SOCK_PATH, DEFAULT_UID_ATTR_MAP,
};
use serde_derive::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ConfigInt {
    db_path: Option<String>,
    sock_path: Option<String>,
    task_sock_path: Option<String>,
    conn_timeout: Option<u64>,
    cache_timeout: Option<u64>,
    pam_allowed_login_groups: Option<Vec<String>>,
    default_shell: Option<String>,
    home_prefix: Option<String>,
    home_attr: Option<String>,
    home_alias: Option<String>,
    uid_attr_map: Option<String>,
    gid_attr_map: Option<String>,
}

#[derive(Debug, Copy, Clone)]
pub enum HomeAttr {
    Uuid,
    Spn,
    Name,
}

#[derive(Debug, Copy, Clone)]
pub enum UidAttr {
    Name,
    Spn,
}

#[derive(Debug)]
pub struct KanidmUnixdConfig {
    pub db_path: String,
    pub sock_path: String,
    pub task_sock_path: String,
    pub conn_timeout: u64,
    pub cache_timeout: u64,
    pub pam_allowed_login_groups: Vec<String>,
    pub default_shell: String,
    pub home_prefix: String,
    pub home_attr: HomeAttr,
    pub home_alias: Option<HomeAttr>,
    pub uid_attr_map: UidAttr,
    pub gid_attr_map: UidAttr,
}

impl Default for KanidmUnixdConfig {
    fn default() -> Self {
        KanidmUnixdConfig::new()
    }
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        KanidmUnixdConfig {
            db_path: DEFAULT_DB_PATH.to_string(),
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            task_sock_path: DEFAULT_TASK_SOCK_PATH.to_string(),
            conn_timeout: DEFAULT_CONN_TIMEOUT,
            cache_timeout: DEFAULT_CACHE_TIMEOUT,
            pam_allowed_login_groups: Vec::new(),
            default_shell: DEFAULT_SHELL.to_string(),
            home_prefix: DEFAULT_HOME_PREFIX.to_string(),
            home_attr: DEFAULT_HOME_ATTR,
            home_alias: DEFAULT_HOME_ALIAS,
            uid_attr_map: DEFAULT_UID_ATTR_MAP,
            gid_attr_map: DEFAULT_GID_ATTR_MAP,
        }
    }

    pub fn read_options_from_optional_config<P: AsRef<Path>>(
        self,
        config_path: P,
    ) -> Result<Self, ()> {
        let mut f = match File::open(config_path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Unabled to open config file [{:?}], skipping ...", e);
                return Ok(self);
            }
        };

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .map_err(|e| eprintln!("{:?}", e))?;

        let config: ConfigInt =
            toml::from_str(contents.as_str()).map_err(|e| eprintln!("{:?}", e))?;

        // Now map the values into our config.
        Ok(KanidmUnixdConfig {
            db_path: config.db_path.unwrap_or(self.db_path),
            sock_path: config.sock_path.unwrap_or(self.sock_path),
            task_sock_path: config.task_sock_path.unwrap_or(self.task_sock_path),
            conn_timeout: config.conn_timeout.unwrap_or(self.conn_timeout),
            cache_timeout: config.cache_timeout.unwrap_or(self.cache_timeout),
            pam_allowed_login_groups: config
                .pam_allowed_login_groups
                .unwrap_or(self.pam_allowed_login_groups),
            default_shell: config.default_shell.unwrap_or(self.default_shell),
            home_prefix: config.home_prefix.unwrap_or(self.home_prefix),
            home_attr: config
                .home_attr
                .and_then(|v| match v.as_str() {
                    "uuid" => Some(HomeAttr::Uuid),
                    "spn" => Some(HomeAttr::Spn),
                    "name" => Some(HomeAttr::Name),
                    _ => {
                        warn!("Invalid home_attr configured, using default ...");
                        None
                    }
                })
                .unwrap_or(self.home_attr),
            home_alias: config
                .home_alias
                .and_then(|v| match v.as_str() {
                    "none" => Some(None),
                    "uuid" => Some(Some(HomeAttr::Uuid)),
                    "spn" => Some(Some(HomeAttr::Spn)),
                    "name" => Some(Some(HomeAttr::Name)),
                    _ => {
                        warn!("Invalid home_alias configured, using default ...");
                        None
                    }
                })
                .unwrap_or(self.home_alias),
            uid_attr_map: config
                .uid_attr_map
                .and_then(|v| match v.as_str() {
                    "spn" => Some(UidAttr::Spn),
                    "name" => Some(UidAttr::Name),
                    _ => {
                        warn!("Invalid uid_attr_map configured, using default ...");
                        None
                    }
                })
                .unwrap_or(self.uid_attr_map),
            gid_attr_map: config
                .gid_attr_map
                .and_then(|v| match v.as_str() {
                    "spn" => Some(UidAttr::Spn),
                    "name" => Some(UidAttr::Name),
                    _ => {
                        warn!("Invalid gid_attr_map configured, using default ...");
                        None
                    }
                })
                .unwrap_or(self.gid_attr_map),
        })
    }
}
