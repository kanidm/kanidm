use std::env;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

#[cfg(all(target_family = "unix", feature = "selinux"))]
use crate::selinux_util;
use crate::unix_passwd::UnixIntegrationError;

use serde::Deserialize;

use crate::constants::{
    DEFAULT_CACHE_TIMEOUT, DEFAULT_CONN_TIMEOUT, DEFAULT_DB_PATH, DEFAULT_GID_ATTR_MAP,
    DEFAULT_HOME_ALIAS, DEFAULT_HOME_ATTR, DEFAULT_HOME_PREFIX, DEFAULT_SELINUX, DEFAULT_SHELL,
    DEFAULT_SOCK_PATH, DEFAULT_TASK_SOCK_PATH, DEFAULT_TPM_TCTI_NAME, DEFAULT_UID_ATTR_MAP,
    DEFAULT_USE_ETC_SKEL,
};

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
    use_etc_skel: Option<bool>,
    uid_attr_map: Option<String>,
    gid_attr_map: Option<String>,
    selinux: Option<bool>,
    #[serde(default)]
    allow_local_account_override: Vec<String>,
    tpm_tcti_name: Option<String>,
    tpm_policy: Option<String>,
}

#[derive(Debug, Copy, Clone)]
pub enum HomeAttr {
    Uuid,
    Spn,
    Name,
}

impl Display for HomeAttr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                HomeAttr::Uuid => "UUID",
                HomeAttr::Spn => "SPN",
                HomeAttr::Name => "Name",
            }
        )
    }
}

#[derive(Debug, Copy, Clone)]
pub enum UidAttr {
    Name,
    Spn,
}

impl Display for UidAttr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                UidAttr::Name => "Name",
                UidAttr::Spn => "SPN",
            }
        )
    }
}

#[derive(Debug, Clone, Default)]
pub enum TpmPolicy {
    #[default]
    Ignore,
    IfPossible(String),
    Required(String),
}

impl Display for TpmPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmPolicy::Ignore => write!(f, "Ignore"),
            TpmPolicy::IfPossible(p) => {
                write!(f, "IfPossible ({})", p)
            }
            TpmPolicy::Required(p) => {
                write!(f, "Required ({})", p)
            }
        }
    }
}

#[derive(Debug)]
pub struct KanidmUnixdConfig {
    pub db_path: String,
    pub sock_path: String,
    pub task_sock_path: String,
    pub conn_timeout: u64,
    pub cache_timeout: u64,
    pub unix_sock_timeout: u64,
    pub pam_allowed_login_groups: Vec<String>,
    pub default_shell: String,
    pub home_prefix: String,
    pub home_attr: HomeAttr,
    pub home_alias: Option<HomeAttr>,
    pub use_etc_skel: bool,
    pub uid_attr_map: UidAttr,
    pub gid_attr_map: UidAttr,
    pub selinux: bool,
    pub tpm_policy: TpmPolicy,
    pub allow_local_account_override: Vec<String>,
}

impl Default for KanidmUnixdConfig {
    fn default() -> Self {
        KanidmUnixdConfig::new()
    }
}

impl Display for KanidmUnixdConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "db_path: {}", &self.db_path)?;
        writeln!(f, "sock_path: {}", self.sock_path)?;
        writeln!(f, "task_sock_path: {}", self.task_sock_path)?;
        writeln!(f, "conn_timeout: {}", self.conn_timeout)?;
        writeln!(f, "unix_sock_timeout: {}", self.unix_sock_timeout)?;
        writeln!(f, "cache_timeout: {}", self.cache_timeout)?;
        writeln!(
            f,
            "pam_allowed_login_groups: {:#?}",
            self.pam_allowed_login_groups
        )?;
        writeln!(f, "default_shell: {}", self.default_shell)?;
        writeln!(f, "home_prefix: {}", self.home_prefix)?;
        writeln!(f, "home_attr: {}", self.home_attr)?;
        match self.home_alias {
            Some(val) => writeln!(f, "home_alias: {}", val)?,
            None => writeln!(f, "home_alias: unset")?,
        }

        writeln!(f, "uid_attr_map: {}", self.uid_attr_map)?;
        writeln!(f, "gid_attr_map: {}", self.gid_attr_map)?;

        writeln!(f, "selinux: {}", self.selinux)?;
        writeln!(f, "tpm_policy: {}", self.tpm_policy)?;
        writeln!(
            f,
            "allow_local_account_override: {:#?}",
            self.allow_local_account_override
        )
    }
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        let db_path = match env::var("KANIDM_DB_PATH") {
            Ok(val) => val,
            Err(_) => DEFAULT_DB_PATH.into(),
        };
        KanidmUnixdConfig {
            db_path,
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            task_sock_path: DEFAULT_TASK_SOCK_PATH.to_string(),
            conn_timeout: DEFAULT_CONN_TIMEOUT,
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cache_timeout: DEFAULT_CACHE_TIMEOUT,
            pam_allowed_login_groups: Vec::new(),
            default_shell: DEFAULT_SHELL.to_string(),
            home_prefix: DEFAULT_HOME_PREFIX.to_string(),
            home_attr: DEFAULT_HOME_ATTR,
            home_alias: DEFAULT_HOME_ALIAS,
            use_etc_skel: DEFAULT_USE_ETC_SKEL,
            uid_attr_map: DEFAULT_UID_ATTR_MAP,
            gid_attr_map: DEFAULT_GID_ATTR_MAP,
            selinux: DEFAULT_SELINUX,
            tpm_policy: TpmPolicy::default(),
            allow_local_account_override: Vec::default(),
        }
    }

    pub fn read_options_from_optional_config<P: AsRef<Path> + std::fmt::Debug>(
        self,
        config_path: P,
    ) -> Result<Self, UnixIntegrationError> {
        debug!("Attempting to load configuration from {:#?}", &config_path);
        let mut f = match File::open(&config_path) {
            Ok(f) => {
                debug!("Successfully opened configuration file {:#?}", &config_path);
                f
            }
            Err(e) => {
                match e.kind() {
                    ErrorKind::NotFound => {
                        debug!(
                            "Configuration file {:#?} not found, skipping.",
                            &config_path
                        );
                    }
                    ErrorKind::PermissionDenied => {
                        warn!(
                            "Permission denied loading configuration file {:#?}, skipping.",
                            &config_path
                        );
                    }
                    _ => {
                        debug!(
                            "Unable to open config file {:#?} [{:?}], skipping ...",
                            &config_path, e
                        );
                    }
                };
                return Ok(self);
            }
        };

        let mut contents = String::new();
        f.read_to_string(&mut contents).map_err(|e| {
            error!("{:?}", e);
            UnixIntegrationError
        })?;

        let config: ConfigInt = toml::from_str(contents.as_str()).map_err(|e| {
            error!("{:?}", e);
            UnixIntegrationError
        })?;

        // Now map the values into our config.
        Ok(KanidmUnixdConfig {
            db_path: config.db_path.unwrap_or(self.db_path),
            sock_path: config.sock_path.unwrap_or(self.sock_path),
            task_sock_path: config.task_sock_path.unwrap_or(self.task_sock_path),
            conn_timeout: config.conn_timeout.unwrap_or(self.conn_timeout),
            unix_sock_timeout: config.conn_timeout.unwrap_or(self.conn_timeout) * 2,
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
            use_etc_skel: config.use_etc_skel.unwrap_or(self.use_etc_skel),
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
            selinux: match config.selinux.unwrap_or(self.selinux) {
                #[cfg(all(target_family = "unix", feature = "selinux"))]
                true => selinux_util::supported(),
                _ => false,
            },
            tpm_policy: config
                .tpm_policy
                .and_then(|v| {
                    let tpm_tcti_name = config
                        .tpm_tcti_name
                        .unwrap_or(DEFAULT_TPM_TCTI_NAME.to_string());
                    match v.as_str() {
                        "ignore" => Some(TpmPolicy::Ignore),
                        "if_possible" => Some(TpmPolicy::IfPossible(tpm_tcti_name)),
                        "required" => Some(TpmPolicy::Required(tpm_tcti_name)),
                        _ => {
                            warn!("Invalid tpm_policy configured, using default ...");
                            None
                        }
                    }
                })
                .unwrap_or(self.tpm_policy),
            allow_local_account_override: config.allow_local_account_override,
        })
    }
}
