//! The server configuration as processed from the startup wrapper. This controls a number of
//! variables that determine how our backends, query server, and frontends are configured.
//!
//! These components should be "per server". Any "per domain" config should be in the system
//! or domain entries that are able to be replicated.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use kanidm_proto::constants::DEFAULT_SERVER_ADDRESS;
use kanidm_proto::internal::FsType;
use kanidm_proto::messages::ConsoleOutputMode;

use serde::Deserialize;
use sketching::LogLevel;
use url::Url;

use crate::repl::config::ReplicationConfiguration;

#[derive(Deserialize, Debug, Clone)]
pub struct OnlineBackup {
    /// The destination folder for your backups
    pub path: String,
    #[serde(default = "default_online_backup_schedule")]
    /// The schedule to run online backups (see <https://crontab.guru/>), defaults to @daily
    ///
    /// Examples:
    ///
    /// - every day at 22:00 UTC (default): `"00 22 * * *"`
    /// - every 6th hours (four times a day) at 3 minutes past the hour, :
    /// `"03 */6 * * *"`
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
}

impl Default for OnlineBackup {
    fn default() -> Self {
        OnlineBackup {
            path: "/dev/null".to_string(),
            schedule: default_online_backup_schedule(),
            versions: default_online_backup_versions(),
        }
    }
}

fn default_online_backup_schedule() -> String {
    "@daily".to_string()
}

fn default_online_backup_versions() -> usize {
    7
}

#[derive(Deserialize, Debug, Clone)]
pub struct TlsConfiguration {
    pub chain: String,
    pub key: String,
}

/// This is the Server Configuration as read from `server.toml`.
///
/// NOTE: not all flags or values from the internal [Configuration] object are exposed via this structure
/// to prevent certain settings being set (e.g. integration test modes)
///
/// If you want to set these as environment variables, prefix them with `KANIDM_` and they will be picked up. This doesn't include replication peer config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Kanidm Domain, eg `kanidm.example.com`.
    pub domain: String,
    /// The user-facing HTTPS URL for this server, eg <https://idm.example.com>
    // TODO  -this should be URL
    pub origin: String,
    /// File path of the database file
    pub db_path: String,
    /// The file path to the TLS Certificate Chain
    pub tls_chain: Option<String>,
    /// The file path to the TLS Private Key
    pub tls_key: Option<String>,

    /// The listener address for the HTTPS server.
    ///
    /// eg. `[::]:8443` or `127.0.0.1:8443`. Defaults to [kanidm_proto::constants::DEFAULT_SERVER_ADDRESS]
    pub bindaddress: Option<String>,
    /// The listener address for the LDAP server.
    ///
    /// eg. `[::]:3636` or `127.0.0.1:3636`. Defaults to [kanidm_proto::constants::DEFAULT_LDAP_ADDRESS]
    pub ldapbindaddress: Option<String>,

    /// The role of this server, one of write_replica, write_replica_no_ui, read_only_replica
    #[serde(default)]
    pub role: ServerRole,
    /// The log level, one of info, debug, trace. Defaults to "info" if not set.
    pub log_level: Option<LogLevel>,

    /// Backup Configuration, see [OnlineBackup] for details on sub-keys.
    pub online_backup: Option<OnlineBackup>,

    /// Trust the X-Forwarded-For header for client IP address. Defaults to false if unset.
    pub trust_x_forward_for: Option<bool>,

    /// The filesystem type, either "zfs" or "generic". Defaults to "generic" if unset.
    pub db_fs_type: Option<kanidm_proto::internal::FsType>,
    /// The path to the "admin" socket, used for local communication when performing cer ain server control tasks.
    pub adminbindpath: Option<String>,

    /// Don't touch this unless you know what you're doing!
    #[allow(dead_code)]
    db_arc_size: Option<usize>,
    #[serde(default)]

    /// Enable replication, this is a development feature and not yet ready for production use.
    pub i_acknowledge_that_replication_is_in_development: bool,
    #[serde(rename = "replication")]
    /// Replication configuration, this is a development feature and not yet ready for production use.
    pub repl_config: Option<ReplicationConfiguration>,
    /// An optional OpenTelemetry collector (GRPC) url to send trace and log data to, eg http://localhost:4317
    pub otel_grpc_url: Option<String>,
}

impl ServerConfig {
    /// loads the configuration file from the path specified, then overlays fields from environment variables starting with `KANIDM_``
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, std::io::Error> {
        let mut f = File::open(config_path.as_ref()).map_err(|e| {
            eprintln!("Unable to open config file [{:?}] 🥺", e);
            let diag = kanidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            eprintln!("{}", diag);
            e
        })?;

        let mut contents = String::new();
        f.read_to_string(&mut contents).map_err(|e| {
            eprintln!("unable to read contents {:?}", e);
            let diag = kanidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            eprintln!("{}", diag);
            e
        })?;

        let res: ServerConfig = toml::from_str(contents.as_str()).map_err(|e| {
            eprintln!(
                "Unable to parse config from '{:?}': {:?}",
                config_path.as_ref(),
                e
            );
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        let res = res.try_from_env().map_err(|e| {
            println!("Failed to use environment variable config: {e}");
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;

        Ok(res)
    }

    /// Updates the ServerConfig from environment variables starting with `KANIDM_`
    fn try_from_env(mut self) -> Result<Self, String> {
        for (key, value) in std::env::vars() {
            if !key.starts_with("KANIDM_") {
                continue;
            }

            let ignorable_build_fields = [
                "KANIDM_CPU_FLAGS",
                "KANIDM_DEFAULT_CONFIG_PATH",
                "KANIDM_DEFAULT_UNIX_SHELL_PATH",
                "KANIDM_PKG_VERSION",
                "KANIDM_PROFILE_NAME",
                "KANIDM_WEB_UI_PKG_PATH",
            ];

            if ignorable_build_fields.contains(&key.as_str()) {
                #[cfg(any(debug_assertions, test))]
                eprintln!("-- Ignoring build-time env var {}", key);
                continue;
            }

            match key.replace("KANIDM_", "").as_str() {
                "DOMAIN" => {
                    self.domain = value.to_string();
                }
                "ORIGIN" => {
                    self.origin = value.to_string();
                }
                "DB_PATH" => {
                    self.origin = value.to_string();
                }
                "TLS_CHAIN" => {
                    self.tls_chain = Some(value.to_string());
                }
                "TLS_KEY" => {
                    self.tls_key = Some(value.to_string());
                }
                "BINDADDRESS" => {
                    self.bindaddress = Some(value.to_string());
                }
                "LDAPBINDADDRESS" => {
                    self.ldapbindaddress = Some(value.to_string());
                }
                "ROLE" => {
                    self.role = match ServerRole::from_str(&value) {
                        Ok(val) => val,
                        Err(err) => {
                            return Err(format!(
                                "Failed to parse KANIDM_ROLE as ServerRole: {}",
                                err
                            ));
                        }
                    };
                }
                "LOG_LEVEL" => {
                    self.log_level = match LogLevel::from_str(&value) {
                        Ok(val) => Some(val),
                        Err(err) => {
                            return Err(format!(
                                "Failed to parse KANIDM_LOG_LEVEL as LogLevel: {}",
                                err
                            ));
                        }
                    };
                }
                "ONLINE_BACKUP_PATH" => {
                    if let Some(backup) = &mut self.online_backup {
                        backup.path = value.to_string();
                    } else {
                        self.online_backup = Some(OnlineBackup {
                            path: value.to_string(),
                            ..Default::default()
                        });
                    }
                }
                "ONLINE_BACKUP_SCHEDULE" => {
                    if let Some(backup) = &mut self.online_backup {
                        backup.schedule = value.to_string();
                    } else {
                        self.online_backup = Some(OnlineBackup {
                            schedule: value.to_string(),
                            ..Default::default()
                        });
                    }
                }
                "ONLINE_BACKUP_VERSIONS" => {
                    let versions = value.parse().map_err(|_| {
                        "Failed to parse KANIDM_ONLINE_BACKUP_VERSIONS as usize".to_string()
                    })?;
                    if let Some(backup) = &mut self.online_backup {
                        backup.versions = versions;
                    } else {
                        self.online_backup = Some(OnlineBackup {
                            versions,
                            ..Default::default()
                        })
                    }
                }
                "TRUST_X_FORWARD_FOR" => {
                    self.trust_x_forward_for = Some(value.parse().map_err(|_| {
                        "Failed to parse KANIDM_TRUST_X_FORWARD_FOR as bool".to_string()
                    })?);
                }
                "DB_FS_TYPE" => {
                    self.db_fs_type = Some(FsType::try_from(value.as_str()).map_err(|_| {
                        "Failed to parse KANIDM_DB_FS_TYPE env var to valid value!".to_string()
                    })?);
                }
                "DB_ARC_SIZE" => {
                    self.db_arc_size =
                        Some(value.parse().map_err(|_| {
                            "Failed to parse KANIDM_DB_ARC_SIZE as value".to_string()
                        })?);
                }
                "ADMIN_BIND_PATH" => {
                    self.adminbindpath = Some(value.to_string());
                }
                "REPLICATION_ORIGIN" => {
                    let repl_origin = Url::parse(value.as_str()).map_err(|err| {
                        format!("Failed to parse KANIDM_REPLICATION_ORIGIN as URL: {}", err)
                    })?;
                    if let Some(repl) = &mut self.repl_config {
                        repl.origin = repl_origin
                    } else {
                        self.repl_config = Some(ReplicationConfiguration {
                            origin: repl_origin,
                            ..Default::default()
                        });
                    }
                }
                "I_ACKNOWLEDGE_THAT_REPLICATION_IS_IN_DEVELOPMENT" => {
                    self.i_acknowledge_that_replication_is_in_development =
                        value.parse().map_err(|_| {
                            "Failed to parse terribly long confirmation of replication beta-ness!"
                                .to_string()
                        })?;
                }
                "REPLICATION_BINDADDRESS" => {
                    let repl_bind_address = value
                        .parse()
                        .map_err(|_| "Failed to parse replication bind address".to_string())?;
                    if let Some(repl) = &mut self.repl_config {
                        repl.bindaddress = repl_bind_address;
                    } else {
                        self.repl_config = Some(ReplicationConfiguration {
                            bindaddress: repl_bind_address,
                            ..Default::default()
                        });
                    }
                }
                "REPLICATION_TASK_POLL_INTERVAL" => {
                    let poll_interval = Some(value.parse().map_err(|_| {
                        "Failed to parse replication task poll interval as u64".to_string()
                    })?);
                    if let Some(repl) = &mut self.repl_config {
                        repl.task_poll_interval = poll_interval;
                    } else {
                        self.repl_config = Some(ReplicationConfiguration {
                            task_poll_interval: poll_interval,
                            ..Default::default()
                        });
                    }
                }
                "OTEL_GRPC_URL" => {
                    self.otel_grpc_url = Some(value.to_string());
                }

                _ => eprintln!("Ignoring env var {}", key),
            }
        }

        Ok(self)
    }

    /// Return the ARC size for the database, it's something you really shouldn't touch unless you are doing extreme tuning.
    pub fn get_db_arc_size(&self) -> Option<usize> {
        self.db_arc_size
    }
}

#[derive(Debug, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
pub enum ServerRole {
    #[default]
    WriteReplica,
    WriteReplicaNoUI,
    ReadOnlyReplica,
}

impl ToString for ServerRole {
    fn to_string(&self) -> String {
        match self {
            ServerRole::WriteReplica => "write replica".to_string(),
            ServerRole::WriteReplicaNoUI => "write replica (no ui)".to_string(),
            ServerRole::ReadOnlyReplica => "read only replica".to_string(),
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
    pub ldapaddress: Option<String>,
    pub adminbindpath: String,
    pub threads: usize,
    // db type later
    pub db_path: String,
    pub db_fs_type: Option<FsType>,
    pub db_arc_size: Option<usize>,
    pub maximum_request: usize,
    pub trust_x_forward_for: bool,
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

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {}, ", self.address)?;
        write!(f, "domain: {}, ", self.domain)?;
        match &self.ldapaddress {
            Some(la) => write!(f, "ldap address: {}, ", la),
            None => write!(f, "ldap address: disabled, "),
        }?;
        write!(f, "origin: {} ", self.origin)?;
        write!(f, "admin bind path: {}, ", self.adminbindpath)?;
        write!(f, "thread count: {}, ", self.threads)?;
        write!(f, "dbpath: {}, ", self.db_path)?;
        match self.db_arc_size {
            Some(v) => write!(f, "arcsize: {}, ", v),
            None => write!(f, "arcsize: AUTO, "),
        }?;
        write!(f, "max request size: {}b, ", self.maximum_request)?;
        write!(f, "trust X-Forwarded-For: {}, ", self.trust_x_forward_for)?;
        write!(f, "with TLS: {}, ", self.tls_config.is_some())?;
        match &self.online_backup {
            Some(bck) => write!(
                f,
                "online_backup: enabled - schedule: {} versions: {}, ",
                bck.schedule, bck.versions
            ),
            None => write!(f, "online_backup: disabled, "),
        }?;
        write!(
            f,
            "integration mode: {}, ",
            self.integration_test_config.is_some()
        )?;
        write!(f, "console output format: {:?} ", self.output_mode)?;
        write!(f, "log_level: {}", self.log_level.clone().to_string())?;
        write!(f, "role: {}, ", self.role.to_string())?;
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

impl Default for Configuration {
    fn default() -> Self {
        Self::new()
    }
}

impl Configuration {
    pub fn new() -> Self {
        Configuration {
            address: DEFAULT_SERVER_ADDRESS.to_string(),
            ldapaddress: None,
            adminbindpath: env!("KANIDM_ADMIN_BIND_PATH").to_string(),
            threads: std::thread::available_parallelism()
                .map(|t| t.get())
                .unwrap_or_else(|_e| {
                    eprintln!("WARNING: Unable to read number of available CPUs, defaulting to 4");
                    4
                }),
            db_path: String::from(""),
            db_fs_type: None,
            db_arc_size: None,
            maximum_request: 256 * 1024, // 256k
            trust_x_forward_for: false,
            tls_config: None,
            integration_test_config: None,
            online_backup: None,
            domain: "idm.example.com".to_string(),
            origin: "https://idm.example.com".to_string(),
            output_mode: ConsoleOutputMode::default(),
            log_level: Default::default(),
            role: ServerRole::WriteReplica,
            repl_config: None,
            integration_repl_config: None,
            otel_grpc_url: None,
        }
    }

    pub fn new_for_test() -> Self {
        Configuration {
            threads: 1,
            ..Configuration::new()
        }
    }

    pub fn update_online_backup(&mut self, cfg: &Option<OnlineBackup>) {
        match cfg {
            None => {}
            Some(cfg) => {
                let path = cfg.path.to_string();
                let schedule = cfg.schedule.to_string();
                let versions = cfg.versions;
                self.online_backup = Some(OnlineBackup {
                    path,
                    schedule,
                    versions,
                })
            }
        }
    }

    pub fn update_log_level(&mut self, level: &Option<LogLevel>) {
        self.log_level = level.unwrap_or_default();
    }

    // Startup config action, used in kanidmd server etc
    pub fn update_config_for_server_mode(&mut self, sconfig: &ServerConfig) {
        #[cfg(any(test, debug_assertions))]
        debug!("update_config_for_server_mode {:?}", sconfig);
        self.update_tls(&sconfig.tls_chain, &sconfig.tls_key);
        self.update_bind(&sconfig.bindaddress);
        self.update_ldapbind(&sconfig.ldapbindaddress);
        self.update_online_backup(&sconfig.online_backup);
        self.update_log_level(&sconfig.log_level);
    }

    pub fn update_trust_x_forward_for(&mut self, t: Option<bool>) {
        self.trust_x_forward_for = t.unwrap_or(false);
    }

    pub fn update_db_path(&mut self, p: &str) {
        self.db_path = p.to_string();
    }

    pub fn update_db_arc_size(&mut self, v: Option<usize>) {
        self.db_arc_size = v
    }

    pub fn update_db_fs_type(&mut self, p: &Option<FsType>) {
        self.db_fs_type = p.to_owned();
    }

    pub fn update_bind(&mut self, b: &Option<String>) {
        self.address = b
            .as_ref()
            .cloned()
            .unwrap_or_else(|| DEFAULT_SERVER_ADDRESS.to_string());
    }

    pub fn update_ldapbind(&mut self, l: &Option<String>) {
        self.ldapaddress = l.clone();
    }

    pub fn update_admin_bind_path(&mut self, p: &Option<String>) {
        if let Some(p) = p {
            self.adminbindpath = p.clone();
        }
    }

    pub fn update_origin(&mut self, o: &str) {
        self.origin = o.to_string();
    }

    pub fn update_domain(&mut self, d: &str) {
        self.domain = d.to_string();
    }

    pub fn update_role(&mut self, r: ServerRole) {
        self.role = r;
    }

    /// Sets the output mode for writing to the console
    pub fn update_output_mode(&mut self, om: ConsoleOutputMode) {
        self.output_mode = om;
    }

    pub fn update_replication_config(&mut self, repl_config: Option<ReplicationConfiguration>) {
        self.repl_config = repl_config;
    }

    pub fn update_tls(&mut self, chain: &Option<String>, key: &Option<String>) {
        match (chain, key) {
            (None, None) => {}
            (Some(chainp), Some(keyp)) => {
                let chain = chainp.to_string();
                let key = keyp.to_string();
                self.tls_config = Some(TlsConfiguration { chain, key })
            }
            _ => {
                eprintln!("ERROR: Invalid TLS configuration - must provide chain and key!");
                std::process::exit(1);
            }
        }
    }
}
