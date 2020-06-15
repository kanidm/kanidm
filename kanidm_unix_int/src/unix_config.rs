use crate::constants::{
    DEFAULT_CACHE_TIMEOUT, DEFAULT_CONN_TIMEOUT, DEFAULT_DB_PATH, DEFAULT_SOCK_PATH,
};
use serde_derive::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct ConfigInt {
    db_path: Option<String>,
    sock_path: Option<String>,
    conn_timeout: Option<u64>,
    cache_timeout: Option<u64>,
    pam_allowed_login_groups: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct KanidmUnixdConfig {
    pub db_path: String,
    pub sock_path: String,
    pub conn_timeout: u64,
    pub cache_timeout: u64,
    pub pam_allowed_login_groups: Vec<String>,
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
            conn_timeout: DEFAULT_CONN_TIMEOUT,
            cache_timeout: DEFAULT_CACHE_TIMEOUT,
            pam_allowed_login_groups: Vec::new(),
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
            conn_timeout: config.conn_timeout.unwrap_or(self.conn_timeout),
            cache_timeout: config.cache_timeout.unwrap_or(self.cache_timeout),
            pam_allowed_login_groups: config
                .pam_allowed_login_groups
                .unwrap_or(self.pam_allowed_login_groups),
        })
    }
}
