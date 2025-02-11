use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use crate::unix_passwd::UnixIntegrationError;

use serde::Deserialize;

use crate::constants::*;

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

#[derive(Debug, Deserialize)]
struct ConfigInt {
    sock_path: Option<String>,
    conn_timeout: Option<u64>,
}

#[derive(Debug)]
pub struct KanidmUnixdConfig {
    pub sock_path: String,
    // pub conn_timeout: u64,
    pub unix_sock_timeout: u64,
}

impl Default for KanidmUnixdConfig {
    fn default() -> Self {
        KanidmUnixdConfig::new()
    }
}

impl Display for KanidmUnixdConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "sock_path: {}", self.sock_path)?;
        writeln!(f, "unix_sock_timeout: {}", self.unix_sock_timeout)
    }
}

impl KanidmUnixdConfig {
    pub fn new() -> Self {
        KanidmUnixdConfig {
            sock_path: DEFAULT_SOCK_PATH.to_string(),
            unix_sock_timeout: DEFAULT_CONN_TIMEOUT * 2,
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

        let unix_sock_timeout = config
            .conn_timeout
            .map(|v| v * 2)
            .unwrap_or(self.unix_sock_timeout);

        // Now map the values into our config.
        Ok(KanidmUnixdConfig {
            sock_path: config.sock_path.unwrap_or(self.sock_path),
            unix_sock_timeout,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_load_example_configs() {
        // Test the various included configs

        let examples_dir = env!("CARGO_MANIFEST_DIR").to_string() + "/../../examples/";

        for file in PathBuf::from(&examples_dir)
            .canonicalize()
            .expect(&format!("Can't find examples dir at {}", examples_dir))
            .read_dir()
            .expect("Can't read examples dir!")
        {
            let file = file.unwrap();
            let filename = file.file_name().into_string().unwrap();
            if filename.starts_with("unixd") {
                print!("Checking that {} parses as a valid config...", filename);

                KanidmUnixdConfig::new()
                    .read_options_from_optional_config(file.path())
                    .expect("Failed to parse");
                println!("OK");
            }
        }
    }
}
