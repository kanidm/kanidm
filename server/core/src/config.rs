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

use kanidm_proto::messages::ConsoleOutputMode;
use serde::{Deserialize, Serialize};
use sketching::tracing_subscriber::EnvFilter;

#[derive(Serialize, Deserialize, Debug)]
pub struct IntegrationTestConfig {
    pub admin_user: String,
    pub admin_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OnlineBackup {
    pub path: String,
    #[serde(default = "default_online_backup_schedule")]
    pub schedule: String,
    #[serde(default = "default_online_backup_versions")]
    pub versions: usize,
}

fn default_online_backup_schedule() -> String {
    "@daily".to_string()
}

fn default_online_backup_versions() -> usize {
    7
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsConfiguration {
    pub chain: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub bindaddress: Option<String>,
    pub ldapbindaddress: Option<String>,
    pub trust_x_forward_for: Option<bool>,
    // pub threads: Option<usize>,
    pub db_path: String,
    pub db_fs_type: Option<String>,
    pub db_arc_size: Option<usize>,
    pub tls_chain: Option<String>,
    pub tls_key: Option<String>,
    pub online_backup: Option<OnlineBackup>,
    pub domain: String,
    pub origin: String,
    #[serde(default)]
    pub role: ServerRole,
    pub log_level: Option<LogLevel>,
}

impl ServerConfig {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, ()> {
        let mut f = File::open(config_path).map_err(|e| {
            eprintln!("Unable to open config file [{:?}] 🥺", e);
        })?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)
            .map_err(|e| eprintln!("unable to read contents {:?}", e))?;

        toml::from_str(contents.as_str()).map_err(|e| eprintln!("unable to parse config {:?}", e))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, Eq, PartialEq)]
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

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub enum LogLevel {
    #[default]
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "debug")]
    Debug,
    #[serde(rename = "trace")]
    Trace,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Err("Must be one of info, debug, trace"),
        }
    }
}

impl ToString for LogLevel {
    fn to_string(&self) -> String {
        match self {
            LogLevel::Info => "info".to_string(),
            LogLevel::Debug => "debug".to_string(),
            LogLevel::Trace => "trace".to_string(),
        }
    }
}

impl Into<EnvFilter> for LogLevel {
    fn into(self) -> EnvFilter {
        match self {
            LogLevel::Info => EnvFilter::new("info"),
            LogLevel::Debug => EnvFilter::new("debug"),
            LogLevel::Trace => EnvFilter::new("trace"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Configuration {
    pub address: String,
    pub ldapaddress: Option<String>,
    pub threads: usize,
    // db type later
    pub db_path: String,
    pub db_fs_type: Option<String>,
    pub db_arc_size: Option<usize>,
    pub maximum_request: usize,
    pub secure_cookies: bool,
    pub trust_x_forward_for: bool,
    pub tls_config: Option<TlsConfiguration>,
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
    pub online_backup: Option<OnlineBackup>,
    pub domain: String,
    pub origin: String,
    pub role: ServerRole,
    pub output_mode: ConsoleOutputMode,
    pub log_level: LogLevel,
}

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {}, ", self.address)
            .and_then(|_| write!(f, "domain: {}, ", self.domain))
            .and_then(|_| match &self.ldapaddress {
                Some(la) => write!(f, "ldap address: {}, ", la),
                None => write!(f, "ldap address: disabled, "),
            })
            .and_then(|_| write!(f, "thread count: {}, ", self.threads))
            .and_then(|_| write!(f, "dbpath: {}, ", self.db_path))
            .and_then(|_| match self.db_arc_size {
                Some(v) => write!(f, "arcsize: {}, ", v),
                None => write!(f, "arcsize: AUTO, "),
            })
            .and_then(|_| write!(f, "max request size: {}b, ", self.maximum_request))
            .and_then(|_| write!(f, "secure cookies: {}, ", self.secure_cookies))
            .and_then(|_| write!(f, "trust X-Forwarded-For: {}, ", self.trust_x_forward_for))
            .and_then(|_| write!(f, "with TLS: {}, ", self.tls_config.is_some()))
            // TODO: include the backup timings
            .and_then(|_| match &self.online_backup {
                Some(_) => write!(f, "online_backup: enabled, "),
                None => write!(f, "online_backup: disabled, "),
            })
            .and_then(|_| write!(f, "role: {}, ", self.role.to_string()))
            .and_then(|_| {
                write!(
                    f,
                    "integration mode: {}, ",
                    self.integration_test_config.is_some()
                )
            })
            .and_then(|_| write!(f, "console output format: {:?} ", self.output_mode))
            .and_then(|_| write!(f, "log_level: {}", self.log_level.clone().to_string()))
    }
}

impl Configuration {
    pub fn new() -> Self {
        Configuration {
            address: String::from("127.0.0.1:8080"),
            ldapaddress: None,
            threads: std::thread::available_parallelism()
                .map(|t| t.get())
                .unwrap_or_else(|_e| {
                    eprintln!("WARNING: Unable to read number of available CPUs, defaulting to 1");
                    1
                }),
            db_path: String::from(""),
            db_fs_type: None,
            db_arc_size: None,
            maximum_request: 256 * 1024, // 256k
            // log path?
            // default true in prd
            secure_cookies: !cfg!(test),
            trust_x_forward_for: false,
            tls_config: None,
            integration_test_config: None,
            online_backup: None,
            domain: "idm.example.com".to_string(),
            origin: "https://idm.example.com".to_string(),
            role: ServerRole::WriteReplica,
            output_mode: ConsoleOutputMode::default(),
            log_level: Default::default(),
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
        let level = level.clone();
        self.log_level = level.unwrap_or_default();
    }

    // Startup config action, used in kanidmd server etc
    pub fn update_config_for_server_mode(&mut self, sconfig: &ServerConfig) {
        #[cfg(debug_assertions)]
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

    pub fn update_db_fs_type(&mut self, p: &Option<String>) {
        self.db_fs_type = p.as_ref().map(|v| v.to_lowercase());
    }

    pub fn update_bind(&mut self, b: &Option<String>) {
        self.address = b
            .as_ref()
            .cloned()
            .unwrap_or_else(|| String::from("127.0.0.1:8080"));
    }

    pub fn update_ldapbind(&mut self, l: &Option<String>) {
        self.ldapaddress = l.clone();
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
