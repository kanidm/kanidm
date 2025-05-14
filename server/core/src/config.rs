//! The server configuration as processed from the startup wrapper. This controls a number of
//! variables that determine how our backends, query server, and frontends are configured.
//!
//! These components should be "per server". Any "per domain" config should be in the system
//! or domain entries that are able to be replicated.

use cidr::IpCidr;
use kanidm_proto::constants::DEFAULT_SERVER_ADDRESS;
use kanidm_proto::internal::FsType;
use kanidm_proto::messages::ConsoleOutputMode;
use serde::Deserialize;
use sketching::LogLevel;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

use crate::repl::config::ReplicationConfiguration;

#[derive(Debug, Deserialize)]
struct VersionDetection {
    #[serde(default)]
    version: Version,
}

#[derive(Debug, Deserialize, Default)]
// #[serde(tag = "version")]
pub enum Version {
    #[serde(rename = "2")]
    V2,

    #[default]
    Legacy,
}

// Allowed as the large enum is only short lived at startup to the true config
#[allow(clippy::large_enum_variant)]
pub enum ServerConfigUntagged {
    Version(ServerConfigVersion),
    Legacy(ServerConfig),
}

pub enum ServerConfigVersion {
    V2 { values: ServerConfigV2 },
}

#[derive(Deserialize, Debug, Clone)]
pub struct OnlineBackup {
    /// The destination folder for your backups, defaults to the db_path dir if not set
    pub path: Option<PathBuf>,
    /// The schedule to run online backups (see <https://crontab.guru/>), defaults to @daily
    ///
    /// Examples:
    ///
    /// - every day at 22:00 UTC (default): `"00 22 * * *"`
    /// - every 6th hours (four times a day) at 3 minutes past the hour, :
    ///   `"03 */6 * * *"`
    ///
    /// We also support non standard cron syntax, with the following format:
    ///
    /// `<sec>  <min>   <hour>   <day of month>   <month>   <day of week>   <year>`
    ///
    /// eg:
    /// - `1 2 3 5 12 * 2023` would only back up once on the 5th of December 2023 at 03:02:01am.
    /// - `3 2 1 * * Mon *` backs up every Monday at 03:02:01am.
    ///
    /// (it's very similar to the standard cron syntax, it just allows to specify the seconds at the beginning and the year at the end)
    pub schedule: String,
    #[serde(default = "default_online_backup_versions")]
    /// How many past backup versions to keep, defaults to 7
    pub versions: usize,
    /// Enabled by default
    #[serde(default = "default_online_backup_enabled")]
    pub enabled: bool,
}

impl Default for OnlineBackup {
    fn default() -> Self {
        OnlineBackup {
            path: None, // This makes it revert to the kanidm_db path
            schedule: default_online_backup_schedule(),
            versions: default_online_backup_versions(),
            enabled: default_online_backup_enabled(),
        }
    }
}

fn default_online_backup_enabled() -> bool {
    true
}

fn default_online_backup_schedule() -> String {
    "@daily".to_string()
}

fn default_online_backup_versions() -> usize {
    7
}

#[derive(Deserialize, Debug, Clone)]
pub struct TlsConfiguration {
    pub chain: PathBuf,
    pub key: PathBuf,
    pub client_ca: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub enum LdapAddressInfo {
    #[default]
    None,
    #[serde(rename = "proxy-v2")]
    ProxyV2(Vec<IpCidr>),
}

impl LdapAddressInfo {
    pub fn trusted_proxy_v2(&self) -> Option<Vec<IpCidr>> {
        if let Self::ProxyV2(trusted) = self {
            Some(trusted.clone())
        } else {
            None
        }
    }
}

impl Display for LdapAddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::ProxyV2(trusted) => {
                f.write_str("proxy-v2 [ ")?;
                for ip in trusted {
                    write!(f, "{} ", ip)?;
                }
                f.write_str("]")
            }
        }
    }
}

pub(crate) enum AddressSet {
    NonContiguousIpSet(Vec<IpCidr>),
    All,
}

impl AddressSet {
    pub(crate) fn contains(&self, ip_addr: &IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::NonContiguousIpSet(range) => {
                range.iter().any(|ip_cidr| ip_cidr.contains(ip_addr))
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
pub enum HttpAddressInfo {
    #[default]
    None,
    #[serde(rename = "x-forward-for")]
    XForwardFor(Vec<IpCidr>),
    // IMPORTANT: This is undocumented, and only exists for backwards compat
    // with config v1 which has a boolean toggle for this option.
    #[serde(rename = "x-forward-for-all-source-trusted")]
    XForwardForAllSourcesTrusted,
    #[serde(rename = "proxy-v2")]
    ProxyV2(Vec<IpCidr>),
}

impl HttpAddressInfo {
    pub(crate) fn trusted_x_forward_for(&self) -> Option<AddressSet> {
        match self {
            Self::XForwardForAllSourcesTrusted => Some(AddressSet::All),
            Self::XForwardFor(trusted) => Some(AddressSet::NonContiguousIpSet(trusted.clone())),
            _ => None,
        }
    }

    pub(crate) fn trusted_proxy_v2(&self) -> Option<Vec<IpCidr>> {
        if let Self::ProxyV2(trusted) = self {
            Some(trusted.clone())
        } else {
            None
        }
    }
}

impl Display for HttpAddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),

            Self::XForwardFor(trusted) => {
                f.write_str("x-forward-for [ ")?;
                for ip in trusted {
                    write!(f, "{} ", ip)?;
                }
                f.write_str("]")
            }
            Self::XForwardForAllSourcesTrusted => {
                f.write_str("x-forward-for [ ALL SOURCES TRUSTED ]")
            }
            Self::ProxyV2(trusted) => {
                f.write_str("proxy-v2 [ ")?;
                for ip in trusted {
                    write!(f, "{} ", ip)?;
                }
                f.write_str("]")
            }
        }
    }
}

/// This is the Server Configuration as read from `server.toml` or environment variables.
///
/// Fields noted as "REQUIRED" are required for the server to start, even if they show as optional due to how file parsing works.
///
/// If you want to set these as environment variables, prefix them with `KANIDM_` and they will be picked up. This does not include replication peer config.
///
/// NOTE: not all flags or values from the internal [Configuration] object are exposed via this structure
/// to prevent certain settings being set (e.g. integration test modes)
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// *REQUIRED* - Kanidm Domain, eg `kanidm.example.com`.
    domain: Option<String>,
    /// *REQUIRED* - The user-facing HTTPS URL for this server, eg <https://idm.example.com>
    // TODO  -this should be URL
    origin: Option<String>,
    /// File path of the database file
    db_path: Option<PathBuf>,
    /// The filesystem type, either "zfs" or "generic". Defaults to "generic" if unset. I you change this, run a database vacuum.
    db_fs_type: Option<kanidm_proto::internal::FsType>,

    ///  *REQUIRED* - The file path to the TLS Certificate Chain
    tls_chain: Option<PathBuf>,
    ///  *REQUIRED* - The file path to the TLS Private Key
    tls_key: Option<PathBuf>,

    /// The directory path of the client ca and crl dir.
    tls_client_ca: Option<PathBuf>,

    /// The listener address for the HTTPS server.
    ///
    /// eg. `[::]:8443` or `127.0.0.1:8443`. Defaults to [kanidm_proto::constants::DEFAULT_SERVER_ADDRESS]
    bindaddress: Option<String>,
    /// The listener address for the LDAP server.
    ///
    /// eg. `[::]:3636` or `127.0.0.1:3636`.
    ///
    /// If unset, the LDAP server will be disabled.
    ldapbindaddress: Option<String>,
    /// The role of this server, one of write_replica, write_replica_no_ui, read_only_replica, defaults to [ServerRole::WriteReplica]
    role: Option<ServerRole>,
    /// The log level, one of info, debug, trace. Defaults to "info" if not set.
    log_level: Option<LogLevel>,

    /// Backup Configuration, see [OnlineBackup] for details on sub-keys.
    online_backup: Option<OnlineBackup>,

    /// Trust the X-Forwarded-For header for client IP address. Defaults to false if unset.
    trust_x_forward_for: Option<bool>,

    /// The path to the "admin" socket, used for local communication when performing certain server control tasks. Default is set on build, based on the system target.
    adminbindpath: Option<String>,

    /// The maximum amount of threads the server will use for the async worker pool. Defaults
    /// to std::threads::available_parallelism.
    thread_count: Option<usize>,

    /// Maximum Request Size in bytes
    maximum_request_size_bytes: Option<usize>,

    /// Don't touch this unless you know what you're doing!
    #[allow(dead_code)]
    db_arc_size: Option<usize>,
    #[serde(default)]
    #[serde(rename = "replication")]
    /// Replication configuration, this is a development feature and not yet ready for production use.
    repl_config: Option<ReplicationConfiguration>,
    /// An optional OpenTelemetry collector (GRPC) url to send trace and log data to, eg `http://localhost:4317`. If not set, disables the feature.
    otel_grpc_url: Option<String>,
}

impl ServerConfigUntagged {
    /// loads the configuration file from the path specified, then overlays fields from environment variables starting with `KANIDM_``
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, std::io::Error> {
        // see if we can load it from the config file you asked for
        eprintln!("📜 Using config file: {:?}", config_path.as_ref());
        let mut f: File = File::open(config_path.as_ref()).inspect_err(|e| {
            eprintln!("Unable to open config file [{:?}] 🥺", e);
            let diag = kanidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            eprintln!("{}", diag);
        })?;

        let mut contents = String::new();

        f.read_to_string(&mut contents).inspect_err(|e| {
            eprintln!("unable to read contents {:?}", e);
            let diag = kanidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            eprintln!("{}", diag);
        })?;

        // First, can we detect the config version?
        let config_version = toml::from_str::<VersionDetection>(contents.as_str())
            .map(|vd| vd.version)
            .map_err(|err| {
                eprintln!(
                    "Unable to parse config version from '{:?}': {:?}",
                    config_path.as_ref(),
                    err
                );
                std::io::Error::new(std::io::ErrorKind::InvalidData, err)
            })?;

        match config_version {
            Version::V2 => toml::from_str::<ServerConfigV2>(contents.as_str())
                .map(|values| ServerConfigUntagged::Version(ServerConfigVersion::V2 { values })),
            Version::Legacy => {
                toml::from_str::<ServerConfig>(contents.as_str()).map(ServerConfigUntagged::Legacy)
            }
        }
        .map_err(|err| {
            eprintln!(
                "Unable to parse config from '{:?}': {:?}",
                config_path.as_ref(),
                err
            );
            std::io::Error::new(std::io::ErrorKind::InvalidData, err)
        })
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfigV2 {
    #[allow(dead_code)]
    version: String,
    domain: Option<String>,
    origin: Option<String>,
    db_path: Option<PathBuf>,
    db_fs_type: Option<kanidm_proto::internal::FsType>,
    tls_chain: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    bindaddress: Option<String>,
    ldapbindaddress: Option<String>,
    role: Option<ServerRole>,
    log_level: Option<LogLevel>,
    online_backup: Option<OnlineBackup>,

    http_client_address_info: Option<HttpAddressInfo>,
    ldap_client_address_info: Option<LdapAddressInfo>,

    adminbindpath: Option<String>,
    thread_count: Option<usize>,
    maximum_request_size_bytes: Option<usize>,
    #[allow(dead_code)]
    db_arc_size: Option<usize>,
    #[serde(default)]
    #[serde(rename = "replication")]
    repl_config: Option<ReplicationConfiguration>,
    otel_grpc_url: Option<String>,
}

#[derive(Default)]
pub struct CliConfig {
    pub output_mode: Option<ConsoleOutputMode>,
}

#[derive(Default)]
pub struct EnvironmentConfig {
    domain: Option<String>,
    origin: Option<String>,
    db_path: Option<PathBuf>,
    tls_chain: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    bindaddress: Option<String>,
    ldapbindaddress: Option<String>,
    role: Option<ServerRole>,
    log_level: Option<LogLevel>,
    online_backup: Option<OnlineBackup>,
    trust_x_forward_for: Option<bool>,
    db_fs_type: Option<kanidm_proto::internal::FsType>,
    adminbindpath: Option<String>,
    db_arc_size: Option<usize>,
    repl_config: Option<ReplicationConfiguration>,
    otel_grpc_url: Option<String>,
}

impl EnvironmentConfig {
    /// Updates the ServerConfig from environment variables starting with `KANIDM_`
    pub fn new() -> Result<Self, String> {
        let mut env_config = Self::default();

        for (key, value) in std::env::vars() {
            let Some(key) = key.strip_prefix("KANIDM_") else {
                continue;
            };

            let ignorable_build_fields = [
                "CPU_FLAGS",
                "DEFAULT_CONFIG_PATH",
                "DEFAULT_UNIX_SHELL_PATH",
                "HTMX_UI_PKG_PATH",
                "PKG_VERSION",
                "PKG_VERSION_HASH",
                "PRE_RELEASE",
                "PROFILE_NAME",
            ];

            if ignorable_build_fields.contains(&key) {
                #[cfg(any(debug_assertions, test))]
                eprintln!("-- Ignoring build-time env var KANIDM_{key}");
                continue;
            }

            match key {
                "DOMAIN" => {
                    env_config.domain = Some(value.to_string());
                }
                "ORIGIN" => {
                    env_config.origin = Some(value.to_string());
                }
                "DB_PATH" => {
                    env_config.db_path = Some(PathBuf::from(value.to_string()));
                }
                "TLS_CHAIN" => {
                    env_config.tls_chain = Some(PathBuf::from(value.to_string()));
                }
                "TLS_KEY" => {
                    env_config.tls_key = Some(PathBuf::from(value.to_string()));
                }
                "TLS_CLIENT_CA" => {
                    env_config.tls_client_ca = Some(PathBuf::from(value.to_string()));
                }
                "BINDADDRESS" => {
                    env_config.bindaddress = Some(value.to_string());
                }
                "LDAPBINDADDRESS" => {
                    env_config.ldapbindaddress = Some(value.to_string());
                }
                "ROLE" => {
                    env_config.role = Some(ServerRole::from_str(&value).map_err(|err| {
                        format!("Failed to parse KANIDM_ROLE as ServerRole: {}", err)
                    })?);
                }
                "LOG_LEVEL" => {
                    env_config.log_level = LogLevel::from_str(&value)
                        .map_err(|err| {
                            format!("Failed to parse KANIDM_LOG_LEVEL as LogLevel: {}", err)
                        })
                        .ok();
                }
                "ONLINE_BACKUP_PATH" => {
                    if let Some(backup) = &mut env_config.online_backup {
                        backup.path = Some(PathBuf::from(value.to_string()));
                    } else {
                        env_config.online_backup = Some(OnlineBackup {
                            path: Some(PathBuf::from(value.to_string())),
                            ..Default::default()
                        });
                    }
                }
                "ONLINE_BACKUP_SCHEDULE" => {
                    if let Some(backup) = &mut env_config.online_backup {
                        backup.schedule = value.to_string();
                    } else {
                        env_config.online_backup = Some(OnlineBackup {
                            schedule: value.to_string(),
                            ..Default::default()
                        });
                    }
                }
                "ONLINE_BACKUP_VERSIONS" => {
                    let versions = value.parse().map_err(|_| {
                        "Failed to parse KANIDM_ONLINE_BACKUP_VERSIONS as usize".to_string()
                    })?;
                    if let Some(backup) = &mut env_config.online_backup {
                        backup.versions = versions;
                    } else {
                        env_config.online_backup = Some(OnlineBackup {
                            versions,
                            ..Default::default()
                        })
                    }
                }
                "TRUST_X_FORWARD_FOR" => {
                    env_config.trust_x_forward_for = value
                        .parse()
                        .map_err(|_| {
                            "Failed to parse KANIDM_TRUST_X_FORWARD_FOR as bool".to_string()
                        })
                        .ok();
                }
                "DB_FS_TYPE" => {
                    env_config.db_fs_type = FsType::try_from(value.as_str())
                        .map_err(|_| {
                            "Failed to parse KANIDM_DB_FS_TYPE env var to valid value!".to_string()
                        })
                        .ok();
                }
                "DB_ARC_SIZE" => {
                    env_config.db_arc_size = value
                        .parse()
                        .map_err(|_| "Failed to parse KANIDM_DB_ARC_SIZE as value".to_string())
                        .ok();
                }
                "ADMIN_BIND_PATH" => {
                    env_config.adminbindpath = Some(value.to_string());
                }
                "REPLICATION_ORIGIN" => {
                    let repl_origin = Url::parse(value.as_str()).map_err(|err| {
                        format!("Failed to parse KANIDM_REPLICATION_ORIGIN as URL: {}", err)
                    })?;
                    if let Some(repl) = &mut env_config.repl_config {
                        repl.origin = repl_origin
                    } else {
                        env_config.repl_config = Some(ReplicationConfiguration {
                            origin: repl_origin,
                            ..Default::default()
                        });
                    }
                }
                "REPLICATION_BINDADDRESS" => {
                    let repl_bind_address = value
                        .parse()
                        .map_err(|_| "Failed to parse replication bind address".to_string())?;
                    if let Some(repl) = &mut env_config.repl_config {
                        repl.bindaddress = repl_bind_address;
                    } else {
                        env_config.repl_config = Some(ReplicationConfiguration {
                            bindaddress: repl_bind_address,
                            ..Default::default()
                        });
                    }
                }
                "REPLICATION_TASK_POLL_INTERVAL" => {
                    let poll_interval = value
                        .parse()
                        .map_err(|_| {
                            "Failed to parse replication task poll interval as u64".to_string()
                        })
                        .ok();
                    if let Some(repl) = &mut env_config.repl_config {
                        repl.task_poll_interval = poll_interval;
                    } else {
                        env_config.repl_config = Some(ReplicationConfiguration {
                            task_poll_interval: poll_interval,
                            ..Default::default()
                        });
                    }
                }
                "OTEL_GRPC_URL" => {
                    env_config.otel_grpc_url = Some(value.to_string());
                }

                _ => eprintln!("Ignoring env var KANIDM_{key}"),
            }
        }

        Ok(env_config)
    }
}

#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
pub enum ServerRole {
    #[default]
    WriteReplica,
    WriteReplicaNoUI,
    ReadOnlyReplica,
}

impl Display for ServerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerRole::WriteReplica => f.write_str("write replica"),
            ServerRole::WriteReplicaNoUI => f.write_str("write replica (no ui)"),
            ServerRole::ReadOnlyReplica => f.write_str("read only replica"),
        }
    }
}

impl FromStr for ServerRole {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "write_replica" => Ok(ServerRole::WriteReplica),
            "write_replica_no_ui" => Ok(ServerRole::WriteReplicaNoUI),
            "read_only_replica" => Ok(ServerRole::ReadOnlyReplica),
            _ => Err("Must be one of write_replica, write_replica_no_ui, read_only_replica"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntegrationTestConfig {
    pub admin_user: String,
    pub admin_password: String,
    pub idm_admin_user: String,
    pub idm_admin_password: String,
}

#[derive(Debug, Clone)]
pub struct IntegrationReplConfig {
    // We can bake in a private key for mTLS here.
    // pub private_key: PKey

    // We might need some condition variables / timers to force replication
    // events? Or a channel to submit with oneshot responses.
}

/// The internal configuration of the server. User-facing configuration is in [ServerConfig], as the configuration file is parsed by that object.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub address: String,
    pub ldapbindaddress: Option<String>,
    pub adminbindpath: String,
    pub threads: usize,
    // db type later
    pub db_path: Option<PathBuf>,
    pub db_fs_type: Option<FsType>,
    pub db_arc_size: Option<usize>,
    pub maximum_request: usize,

    pub http_client_address_info: HttpAddressInfo,
    pub ldap_client_address_info: LdapAddressInfo,

    pub tls_config: Option<TlsConfiguration>,
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
    pub online_backup: Option<OnlineBackup>,
    pub domain: String,
    pub origin: String,
    pub role: ServerRole,
    pub output_mode: ConsoleOutputMode,
    pub log_level: LogLevel,
    /// Replication settings.
    pub repl_config: Option<ReplicationConfiguration>,
    /// This allows internally setting some unsafe options for replication.
    pub integration_repl_config: Option<Box<IntegrationReplConfig>>,
    pub otel_grpc_url: Option<String>,
}

impl Configuration {
    pub fn build() -> ConfigurationBuilder {
        ConfigurationBuilder {
            bindaddress: None,
            ldapbindaddress: None,
            adminbindpath: None,
            threads: std::thread::available_parallelism()
                .map(|t| t.get())
                .unwrap_or_else(|_e| {
                    eprintln!("WARNING: Unable to read number of available CPUs, defaulting to 4");
                    4
                }),
            db_path: None,
            db_fs_type: None,
            db_arc_size: None,
            maximum_request: 256 * 1024, // 256k
            http_client_address_info: HttpAddressInfo::default(),
            ldap_client_address_info: LdapAddressInfo::default(),
            tls_key: None,
            tls_chain: None,
            tls_client_ca: None,
            online_backup: None,
            domain: None,
            origin: None,
            output_mode: None,
            log_level: None,
            role: None,
            repl_config: None,
            otel_grpc_url: None,
        }
    }

    pub fn new_for_test() -> Self {
        Configuration {
            address: DEFAULT_SERVER_ADDRESS.to_string(),
            ldapbindaddress: None,
            adminbindpath: env!("KANIDM_SERVER_ADMIN_BIND_PATH").to_string(),
            threads: 1,
            db_path: None,
            db_fs_type: None,
            db_arc_size: None,
            maximum_request: 256 * 1024, // 256k
            http_client_address_info: HttpAddressInfo::default(),
            ldap_client_address_info: LdapAddressInfo::default(),
            tls_config: None,
            integration_test_config: None,
            online_backup: None,
            domain: "idm.example.com".to_string(),
            origin: "https://idm.example.com".to_string(),
            output_mode: ConsoleOutputMode::default(),
            log_level: LogLevel::default(),
            role: ServerRole::WriteReplica,
            repl_config: None,
            integration_repl_config: None,
            otel_grpc_url: None,
        }
    }
}

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {}, ", self.address)?;
        write!(f, "domain: {}, ", self.domain)?;
        match &self.ldapbindaddress {
            Some(la) => write!(f, "ldap address: {}, ", la),
            None => write!(f, "ldap address: disabled, "),
        }?;
        write!(f, "origin: {} ", self.origin)?;
        write!(f, "admin bind path: {}, ", self.adminbindpath)?;
        write!(f, "thread count: {}, ", self.threads)?;
        write!(
            f,
            "dbpath: {}, ",
            self.db_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or("MEMORY".to_string())
        )?;
        match self.db_arc_size {
            Some(v) => write!(f, "arcsize: {}, ", v),
            None => write!(f, "arcsize: AUTO, "),
        }?;
        write!(f, "max request size: {}b, ", self.maximum_request)?;
        write!(
            f,
            "http client address info: {}, ",
            self.http_client_address_info
        )?;
        write!(
            f,
            "ldap client address info: {}, ",
            self.ldap_client_address_info
        )?;

        write!(f, "with TLS: {}, ", self.tls_config.is_some())?;
        match &self.online_backup {
            Some(bck) => write!(
                f,
                "online_backup: enabled: {} - schedule: {} versions: {} path: {}, ",
                bck.enabled,
                bck.schedule,
                bck.versions,
                bck.path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or("<unset>".to_string())
            ),
            None => write!(f, "online_backup: disabled, "),
        }?;
        write!(
            f,
            "integration mode: {}, ",
            self.integration_test_config.is_some()
        )?;
        write!(f, "console output format: {:?} ", self.output_mode)?;
        write!(f, "log_level: {}", self.log_level)?;
        write!(f, "role: {}, ", self.role)?;
        match &self.repl_config {
            Some(repl) => {
                write!(f, "replication: enabled")?;
                write!(f, "repl_origin: {} ", repl.origin)?;
                write!(f, "repl_address: {} ", repl.bindaddress)?;
                write!(
                    f,
                    "integration repl config mode: {}, ",
                    self.integration_repl_config.is_some()
                )?;
            }
            None => {
                write!(f, "replication: disabled, ")?;
            }
        }
        write!(f, "otel_grpc_url: {:?}", self.otel_grpc_url)?;
        Ok(())
    }
}

/// The internal configuration of the server. User-facing configuration is in [ServerConfig], as the configuration file is parsed by that object.
#[derive(Debug, Clone)]
pub struct ConfigurationBuilder {
    bindaddress: Option<String>,
    ldapbindaddress: Option<String>,
    adminbindpath: Option<String>,
    threads: usize,
    db_path: Option<PathBuf>,
    db_fs_type: Option<FsType>,
    db_arc_size: Option<usize>,
    maximum_request: usize,
    http_client_address_info: HttpAddressInfo,
    ldap_client_address_info: LdapAddressInfo,
    tls_key: Option<PathBuf>,
    tls_chain: Option<PathBuf>,
    tls_client_ca: Option<PathBuf>,
    online_backup: Option<OnlineBackup>,
    domain: Option<String>,
    origin: Option<String>,
    role: Option<ServerRole>,
    output_mode: Option<ConsoleOutputMode>,
    log_level: Option<LogLevel>,
    repl_config: Option<ReplicationConfiguration>,
    otel_grpc_url: Option<String>,
}

impl ConfigurationBuilder {
    #![allow(clippy::needless_pass_by_value)]
    pub fn add_cli_config(mut self, cli_config: CliConfig) -> Self {
        if cli_config.output_mode.is_some() {
            self.output_mode = cli_config.output_mode;
        }

        self
    }

    pub fn add_env_config(mut self, env_config: EnvironmentConfig) -> Self {
        if env_config.bindaddress.is_some() {
            self.bindaddress = env_config.bindaddress;
        }

        if env_config.ldapbindaddress.is_some() {
            self.ldapbindaddress = env_config.ldapbindaddress;
        }

        if env_config.adminbindpath.is_some() {
            self.adminbindpath = env_config.adminbindpath;
        }

        if env_config.db_path.is_some() {
            self.db_path = env_config.db_path;
        }

        if env_config.db_fs_type.is_some() {
            self.db_fs_type = env_config.db_fs_type;
        }

        if env_config.db_arc_size.is_some() {
            self.db_arc_size = env_config.db_arc_size;
        }

        if env_config.trust_x_forward_for == Some(true) {
            self.http_client_address_info = HttpAddressInfo::XForwardForAllSourcesTrusted;
        }

        if env_config.tls_key.is_some() {
            self.tls_key = env_config.tls_key;
        }

        if env_config.tls_chain.is_some() {
            self.tls_chain = env_config.tls_chain;
        }

        if env_config.tls_client_ca.is_some() {
            self.tls_client_ca = env_config.tls_client_ca;
        }

        if env_config.online_backup.is_some() {
            self.online_backup = env_config.online_backup;
        }

        if env_config.domain.is_some() {
            self.domain = env_config.domain;
        }

        if env_config.origin.is_some() {
            self.origin = env_config.origin;
        }

        if env_config.role.is_some() {
            self.role = env_config.role;
        }

        if env_config.log_level.is_some() {
            self.log_level = env_config.log_level;
        }

        if env_config.repl_config.is_some() {
            self.repl_config = env_config.repl_config;
        }

        if env_config.otel_grpc_url.is_some() {
            self.otel_grpc_url = env_config.otel_grpc_url;
        }

        self
    }

    pub fn add_opt_toml_config(self, toml_config: Option<ServerConfigUntagged>) -> Self {
        // Can only proceed if the config is real
        let Some(toml_config) = toml_config else {
            return self;
        };

        match toml_config {
            ServerConfigUntagged::Version(ServerConfigVersion::V2 { values }) => {
                self.add_v2_config(values)
            }
            ServerConfigUntagged::Legacy(config) => self.add_legacy_config(config),
        }
    }

    fn add_legacy_config(mut self, config: ServerConfig) -> Self {
        if config.domain.is_some() {
            self.domain = config.domain;
        }

        if config.origin.is_some() {
            self.origin = config.origin;
        }

        if config.db_path.is_some() {
            self.db_path = config.db_path;
        }

        if config.db_fs_type.is_some() {
            self.db_fs_type = config.db_fs_type;
        }

        if config.tls_key.is_some() {
            self.tls_key = config.tls_key;
        }

        if config.tls_chain.is_some() {
            self.tls_chain = config.tls_chain;
        }

        if config.tls_client_ca.is_some() {
            self.tls_client_ca = config.tls_client_ca;
        }

        if config.bindaddress.is_some() {
            self.bindaddress = config.bindaddress;
        }

        if config.ldapbindaddress.is_some() {
            self.ldapbindaddress = config.ldapbindaddress;
        }

        if config.adminbindpath.is_some() {
            self.adminbindpath = config.adminbindpath;
        }

        if config.role.is_some() {
            self.role = config.role;
        }

        if config.log_level.is_some() {
            self.log_level = config.log_level;
        }

        if let Some(threads) = config.thread_count {
            self.threads = threads;
        }

        if let Some(maximum) = config.maximum_request_size_bytes {
            self.maximum_request = maximum;
        }

        if config.db_arc_size.is_some() {
            self.db_arc_size = config.db_arc_size;
        }

        if config.trust_x_forward_for == Some(true) {
            self.http_client_address_info = HttpAddressInfo::XForwardForAllSourcesTrusted;
        }

        if config.online_backup.is_some() {
            self.online_backup = config.online_backup;
        }

        if config.repl_config.is_some() {
            self.repl_config = config.repl_config;
        }

        if config.otel_grpc_url.is_some() {
            self.otel_grpc_url = config.otel_grpc_url;
        }

        self
    }

    fn add_v2_config(mut self, config: ServerConfigV2) -> Self {
        if config.domain.is_some() {
            self.domain = config.domain;
        }

        if config.origin.is_some() {
            self.origin = config.origin;
        }

        if config.db_path.is_some() {
            self.db_path = config.db_path;
        }

        if config.db_fs_type.is_some() {
            self.db_fs_type = config.db_fs_type;
        }

        if config.tls_key.is_some() {
            self.tls_key = config.tls_key;
        }

        if config.tls_chain.is_some() {
            self.tls_chain = config.tls_chain;
        }

        if config.tls_client_ca.is_some() {
            self.tls_client_ca = config.tls_client_ca;
        }

        if config.bindaddress.is_some() {
            self.bindaddress = config.bindaddress;
        }

        if config.ldapbindaddress.is_some() {
            self.ldapbindaddress = config.ldapbindaddress;
        }

        if config.adminbindpath.is_some() {
            self.adminbindpath = config.adminbindpath;
        }

        if config.role.is_some() {
            self.role = config.role;
        }

        if config.log_level.is_some() {
            self.log_level = config.log_level;
        }

        if let Some(threads) = config.thread_count {
            self.threads = threads;
        }

        if let Some(maximum) = config.maximum_request_size_bytes {
            self.maximum_request = maximum;
        }

        if config.db_arc_size.is_some() {
            self.db_arc_size = config.db_arc_size;
        }

        if let Some(http_client_address_info) = config.http_client_address_info {
            self.http_client_address_info = http_client_address_info
        }

        if let Some(ldap_client_address_info) = config.ldap_client_address_info {
            self.ldap_client_address_info = ldap_client_address_info
        }

        if config.online_backup.is_some() {
            self.online_backup = config.online_backup;
        }

        if config.repl_config.is_some() {
            self.repl_config = config.repl_config;
        }

        if config.otel_grpc_url.is_some() {
            self.otel_grpc_url = config.otel_grpc_url;
        }

        self
    }

    // We always set threads to 1 unless it's the main server.
    pub fn is_server_mode(mut self, is_server: bool) -> Self {
        if is_server {
            self.threads = 1;
        }
        self
    }

    pub fn finish(self) -> Option<Configuration> {
        let ConfigurationBuilder {
            bindaddress,
            ldapbindaddress,
            adminbindpath,
            threads,
            db_path,
            db_fs_type,
            db_arc_size,
            maximum_request,
            http_client_address_info,
            ldap_client_address_info,
            tls_key,
            tls_chain,
            tls_client_ca,
            mut online_backup,
            domain,
            origin,
            role,
            output_mode,
            log_level,
            repl_config,
            otel_grpc_url,
        } = self;

        let tls_config = match (tls_key, tls_chain, tls_client_ca) {
            (Some(key), Some(chain), client_ca) => Some(TlsConfiguration {
                chain,
                key,
                client_ca,
            }),
            _ => {
                eprintln!("ERROR: Tls Private Key and Certificate Chain are required.");
                return None;
            }
        };

        let domain = domain.or_else(|| {
            eprintln!("ERROR: domain was not set.");
            None
        })?;

        let origin = origin.or_else(|| {
            eprintln!("ERROR: origin was not set.");
            None
        })?;

        if let Some(online_backup_ref) = online_backup.as_mut() {
            if online_backup_ref.path.is_none() {
                if let Some(db_path) = db_path.as_ref() {
                    if let Some(db_parent_path) = db_path.parent() {
                        online_backup_ref.path = Some(db_parent_path.to_path_buf());
                    } else {
                        eprintln!("ERROR: when db_path has no parent, and can not be used for online backups.");
                        return None;
                    }
                } else {
                    eprintln!("ERROR: when db_path is unset (in memory) then online backup paths must be declared.");
                    return None;
                }
            }
        };

        // Apply any defaults if needed
        let adminbindpath =
            adminbindpath.unwrap_or(env!("KANIDM_SERVER_ADMIN_BIND_PATH").to_string());
        let address = bindaddress.unwrap_or(DEFAULT_SERVER_ADDRESS.to_string());
        let output_mode = output_mode.unwrap_or_default();
        let role = role.unwrap_or(ServerRole::WriteReplica);
        let log_level = log_level.unwrap_or_default();

        Some(Configuration {
            address,
            ldapbindaddress,
            adminbindpath,
            threads,
            db_path,
            db_fs_type,
            db_arc_size,
            maximum_request,
            http_client_address_info,
            ldap_client_address_info,
            tls_config,
            online_backup,
            domain,
            origin,
            role,
            output_mode,
            log_level,
            repl_config,
            otel_grpc_url,
            integration_repl_config: None,
            integration_test_config: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn assert_cidr_parsing_behaviour() {
        // Assert that we can parse individual hosts, and ranges
        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"127.0.0.1\"").unwrap();
        let expect_ip_cidr = IpCidr::from(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);

        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"127.0.0.0/8\"").unwrap();
        let expect_ip_cidr = IpCidr::from(Ipv4Cidr::new(Ipv4Addr::new(127, 0, 0, 0), 8).unwrap());
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);

        // Same for ipv6
        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"2001:0db8::1\"").unwrap();
        let expect_ip_cidr = IpCidr::from(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001));
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);

        let parsed_ip_cidr: IpCidr = serde_json::from_str("\"2001:0db8::/64\"").unwrap();
        let expect_ip_cidr = IpCidr::from(
            Ipv6Cidr::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 64).unwrap(),
        );
        assert_eq!(parsed_ip_cidr, expect_ip_cidr);
    }
}
