use std::env;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

#[cfg(all(target_family = "unix", feature = "selinux"))]
use crate::selinux_util;
use kanidm_unix_common::unix_passwd::UnixIntegrationError;

pub(crate) use kanidm_unix_common::unix_config::{HomeAttr, UidAttr};

use serde::Deserialize;

use kanidm_unix_common::constants::*;

// Allowed as the large enum is only short lived at startup to the true config
#[allow(clippy::large_enum_variant)]
// This bit of magic lets us deserialise the old config and the new versions.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ConfigUntagged {
    Versioned(ConfigVersion),
    Legacy(ConfigInt),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "version")]
enum ConfigVersion {
    #[serde(rename = "2")]
    V2 {
        #[serde(flatten)]
        values: ConfigV2,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigV2 {
    cache_db_path: Option<String>,
    sock_path: Option<String>,
    task_sock_path: Option<String>,

    cache_timeout: Option<u64>,

    default_shell: Option<String>,
    home_prefix: Option<String>,
    home_mount_prefix: Option<String>,
    home_attr: Option<String>,
    home_alias: Option<String>,
    use_etc_skel: Option<bool>,
    uid_attr_map: Option<String>,
    gid_attr_map: Option<String>,
    selinux: Option<bool>,

    hsm_pin_path: Option<String>,
    hsm_type: Option<String>,
    tpm_tcti_name: Option<String>,

    kanidm: Option<KanidmConfigV2>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GroupMap {
    pub local: String,
    pub with: String,
}

#[derive(Debug, Deserialize)]
struct KanidmConfigV2 {
    conn_timeout: Option<u64>,
    request_timeout: Option<u64>,
    pam_allowed_login_groups: Option<Vec<String>>,
    map_group: Vec<GroupMap>,
}

#[derive(Debug, Deserialize)]
struct ConfigInt {
    db_path: Option<String>,
    sock_path: Option<String>,
    task_sock_path: Option<String>,
    conn_timeout: Option<u64>,
    request_timeout: Option<u64>,
    cache_timeout: Option<u64>,
    pam_allowed_login_groups: Option<Vec<String>>,
    default_shell: Option<String>,
    home_prefix: Option<String>,
    home_mount_prefix: Option<String>,
    home_attr: Option<String>,
    home_alias: Option<String>,
    use_etc_skel: Option<bool>,
    uid_attr_map: Option<String>,
    gid_attr_map: Option<String>,
    selinux: Option<bool>,
    #[serde(default)]
    allow_local_account_override: Vec<String>,

    hsm_pin_path: Option<String>,
    hsm_type: Option<String>,
    tpm_tcti_name: Option<String>,

    // Detect and warn on values in these places.
    #[serde(default)]
    cache_db_path: Option<toml::value::Value>,
    #[serde(default)]
    kanidm: Option<toml::value::Value>,
}

#[derive(Debug, Clone, Default)]
pub enum HsmType {
    #[cfg_attr(not(feature = "tpm"), default)]
    Soft,
    #[cfg_attr(feature = "tpm", default)]
    TpmIfPossible,
    Tpm,
}

impl Display for HsmType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmType::Soft => write!(f, "Soft"),
            HsmType::TpmIfPossible => write!(f, "Tpm if possible"),
            HsmType::Tpm => write!(f, "Tpm"),
        }
    }
}

#[derive(Debug)]
pub struct UnixdConfig {
    pub cache_db_path: String,
    pub sock_path: String,
    pub task_sock_path: String,
    pub cache_timeout: u64,
    pub unix_sock_timeout: u64,
    pub default_shell: String,
    pub home_prefix: PathBuf,
    pub home_mount_prefix: Option<PathBuf>,
    pub home_attr: HomeAttr,
    pub home_alias: Option<HomeAttr>,
    pub use_etc_skel: bool,
    pub uid_attr_map: UidAttr,
    pub gid_attr_map: UidAttr,
    pub selinux: bool,
    pub hsm_type: HsmType,
    pub hsm_pin_path: String,
    pub tpm_tcti_name: String,

    pub kanidm_config: Option<KanidmConfig>,
}

#[derive(Debug)]
pub struct KanidmConfig {
    pub conn_timeout: u64,
    pub request_timeout: u64,
    pub pam_allowed_login_groups: Vec<String>,
    pub map_group: Vec<GroupMap>,
}

impl Default for UnixdConfig {
    fn default() -> Self {
        UnixdConfig::new()
    }
}

impl Display for UnixdConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "cache_db_path: {}", &self.cache_db_path)?;
        writeln!(f, "sock_path: {}", self.sock_path)?;
        writeln!(f, "task_sock_path: {}", self.task_sock_path)?;
        writeln!(f, "unix_sock_timeout: {}", self.unix_sock_timeout)?;
        writeln!(f, "cache_timeout: {}", self.cache_timeout)?;
        writeln!(f, "default_shell: {}", self.default_shell)?;
        writeln!(f, "home_prefix: {:?}", self.home_prefix)?;
        match self.home_mount_prefix.as_deref() {
            Some(val) => writeln!(f, "home_mount_prefix: {:?}", val)?,
            None => writeln!(f, "home_mount_prefix: unset")?,
        }
        writeln!(f, "home_attr: {}", self.home_attr)?;
        match self.home_alias {
            Some(val) => writeln!(f, "home_alias: {}", val)?,
            None => writeln!(f, "home_alias: unset")?,
        }

        writeln!(f, "uid_attr_map: {}", self.uid_attr_map)?;
        writeln!(f, "gid_attr_map: {}", self.gid_attr_map)?;

        writeln!(f, "hsm_type: {}", self.hsm_type)?;
        writeln!(f, "tpm_tcti_name: {}", self.tpm_tcti_name)?;

        writeln!(f, "selinux: {}", self.selinux)?;

        if let Some(kconfig) = &self.kanidm_config {
            writeln!(f, "kanidm: enabled")?;
            writeln!(
                f,
                "kanidm pam_allowed_login_groups: {:#?}",
                kconfig.pam_allowed_login_groups
            )?;
            writeln!(f, "kanidm conn_timeout: {}", kconfig.conn_timeout)?;
            writeln!(f, "kanidm request_timeout: {}", kconfig.request_timeout)?;
        } else {
            writeln!(f, "kanidm: disabled")?;
        };

        Ok(())
    }
}

impl UnixdConfig {
    pub fn new() -> Self {
        let cache_db_path = match env::var("KANIDM_CACHE_DB_PATH") {
            Ok(val) => val,
            Err(_) => DEFAULT_CACHE_DB_PATH.into(),
        };
        let hsm_pin_path = match env::var("KANIDM_HSM_PIN_PATH") {
            Ok(val) => val,
            Err(_) => DEFAULT_HSM_PIN_PATH.into(),
        };

        UnixdConfig {
            cache_db_path,
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            task_sock_path: DEFAULT_TASK_SOCK_PATH.to_string(),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cache_timeout: DEFAULT_CACHE_TIMEOUT,
            default_shell: DEFAULT_SHELL.to_string(),
            home_prefix: DEFAULT_HOME_PREFIX.into(),
            home_mount_prefix: None,
            home_attr: DEFAULT_HOME_ATTR,
            home_alias: DEFAULT_HOME_ALIAS,
            use_etc_skel: DEFAULT_USE_ETC_SKEL,
            uid_attr_map: DEFAULT_UID_ATTR_MAP,
            gid_attr_map: DEFAULT_GID_ATTR_MAP,
            selinux: DEFAULT_SELINUX,
            hsm_pin_path,
            hsm_type: HsmType::default(),
            tpm_tcti_name: DEFAULT_TPM_TCTI_NAME.to_string(),

            kanidm_config: None,
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

        let config: ConfigUntagged = toml::from_str(contents.as_str()).map_err(|e| {
            error!("{:?}", e);
            UnixIntegrationError
        })?;

        match config {
            ConfigUntagged::Legacy(config) => self.apply_from_config_legacy(config),
            ConfigUntagged::Versioned(ConfigVersion::V2 { values }) => {
                self.apply_from_config_v2(values)
            }
        }
    }

    fn apply_from_config_legacy(self, config: ConfigInt) -> Result<Self, UnixIntegrationError> {
        if config.kanidm.is_some() || config.cache_db_path.is_some() {
            error!("You are using version=\"2\" options in a legacy config. THESE WILL NOT WORK.");
            return Err(UnixIntegrationError);
        }

        let map_group = config
            .allow_local_account_override
            .iter()
            .map(|name| GroupMap {
                local: name.clone(),
                with: name.clone(),
            })
            .collect();

        let kanidm_config = Some(KanidmConfig {
            conn_timeout: config.conn_timeout.unwrap_or(DEFAULT_CONN_TIMEOUT),
            request_timeout: config.request_timeout.unwrap_or(DEFAULT_CONN_TIMEOUT * 2),
            pam_allowed_login_groups: config.pam_allowed_login_groups.unwrap_or_default(),
            map_group,
        });

        // Now map the values into our config.
        Ok(UnixdConfig {
            cache_db_path: config.db_path.unwrap_or(self.cache_db_path),
            sock_path: config.sock_path.unwrap_or(self.sock_path),
            task_sock_path: config.task_sock_path.unwrap_or(self.task_sock_path),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cache_timeout: config.cache_timeout.unwrap_or(self.cache_timeout),
            default_shell: config.default_shell.unwrap_or(self.default_shell),
            home_prefix: config
                .home_prefix
                .map(|p| p.into())
                .unwrap_or(self.home_prefix.clone()),
            home_mount_prefix: config.home_mount_prefix.map(|p| p.into()),
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
            hsm_pin_path: config.hsm_pin_path.unwrap_or(self.hsm_pin_path),
            hsm_type: config
                .hsm_type
                .and_then(|v| match v.as_str() {
                    "soft" => Some(HsmType::Soft),
                    "tpm_if_possible" => Some(HsmType::TpmIfPossible),
                    "tpm" => Some(HsmType::Tpm),
                    _ => {
                        warn!("Invalid hsm_type configured, using default ...");
                        None
                    }
                })
                .unwrap_or(self.hsm_type),
            tpm_tcti_name: config
                .tpm_tcti_name
                .unwrap_or(DEFAULT_TPM_TCTI_NAME.to_string()),
            kanidm_config,
        })
    }

    fn apply_from_config_v2(self, config: ConfigV2) -> Result<Self, UnixIntegrationError> {
        let kanidm_config = if let Some(kconfig) = config.kanidm {
            Some(KanidmConfig {
                conn_timeout: kconfig.conn_timeout.unwrap_or(DEFAULT_CONN_TIMEOUT),
                request_timeout: kconfig.request_timeout.unwrap_or(DEFAULT_CONN_TIMEOUT * 2),
                pam_allowed_login_groups: kconfig.pam_allowed_login_groups.unwrap_or_default(),
                map_group: kconfig.map_group,
            })
        } else {
            None
        };

        // Now map the values into our config.
        Ok(UnixdConfig {
            cache_db_path: config.cache_db_path.unwrap_or(self.cache_db_path),
            sock_path: config.sock_path.unwrap_or(self.sock_path),
            task_sock_path: config.task_sock_path.unwrap_or(self.task_sock_path),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
            cache_timeout: config.cache_timeout.unwrap_or(self.cache_timeout),
            default_shell: config.default_shell.unwrap_or(self.default_shell),
            home_prefix: config
                .home_prefix
                .map(|p| p.into())
                .unwrap_or(self.home_prefix.clone()),
            home_mount_prefix: config.home_mount_prefix.map(|p| p.into()),
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
            hsm_pin_path: config.hsm_pin_path.unwrap_or(self.hsm_pin_path),
            hsm_type: config
                .hsm_type
                .and_then(|v| match v.as_str() {
                    "soft" => Some(HsmType::Soft),
                    "tpm_if_possible" => Some(HsmType::TpmIfPossible),
                    "tpm" => Some(HsmType::Tpm),
                    _ => {
                        warn!("Invalid hsm_type configured, using default ...");
                        None
                    }
                })
                .unwrap_or(self.hsm_type),
            tpm_tcti_name: config
                .tpm_tcti_name
                .unwrap_or(DEFAULT_TPM_TCTI_NAME.to_string()),
            kanidm_config,
        })
    }
}
