use crate::utils::SID;
use rand::prelude::*;
use std::path::PathBuf;
use std::fmt;
use num_cpus;

#[derive(Serialize, Deserialize, Debug)]
pub struct IntegrationTestConfig {
    pub admin_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TlsConfiguration {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration {
    pub address: String,
    pub domain: String,
    pub threads: usize,
    // db type later
    pub db_path: String,
    pub maximum_request: usize,
    pub secure_cookies: bool,
    pub tls_config: Option<TlsConfiguration>,
    pub cookie_key: [u8; 32],
    pub server_id: SID,
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
}

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {}, ", self.address)
            .and_then(|_| write!(f, "domain: {}, ", self.domain))
            .and_then(|_| write!(f, "thread count: {}, ", self.threads))
            .and_then(|_| write!(f, "dbpath: {}, ", self.db_path))
            .and_then(|_| write!(f, "max request size: {}b, ", self.maximum_request))
            .and_then(|_| write!(f, "secure cookies: {}, ", self.secure_cookies))
            .and_then(|_| write!(f, "with TLS: {}, ", self.tls_config.is_some()))
            .and_then(|_| write!(f, "server_id: {:?}, ", self.server_id))
        .and_then(|_| write!(f, "integration mode: {}", self.integration_test_config.is_some()))
    }
}

impl Configuration {
    pub fn new() -> Self {
        let mut c = Configuration {
            address: String::from("127.0.0.1:8080"),
            domain: String::from("localhost"),
            threads: num_cpus::get(),
            db_path: String::from(""),
            maximum_request: 262144, // 256k
            // log type
            // log path
            // TODO #63: default true in prd
            secure_cookies: if cfg!(test) { false } else { true },
            tls_config: None,
            cookie_key: [0; 32],
            server_id: [0; 4],
            integration_test_config: None,
        };
        let mut rng = StdRng::from_entropy();

        // Does the sid file exist?
        // yes? Read from it
        // no? write it after we gen the sid.

        rng.fill(&mut c.cookie_key);
        rng.fill(&mut c.server_id);
        c
    }

    pub fn update_db_path(&mut self, p: &PathBuf) {
        match p.to_str() {
            Some(p) => self.db_path = p.to_string(),
            None => {
                error!("Invalid DB path supplied");
                std::process::exit(1);
            }
        }
    }

    pub fn update_tls(&mut self, ca: &Option<PathBuf>, cert: &Option<PathBuf>, key: &Option<PathBuf>) {
        match (ca, cert, key) {
            (None, None, None) => {}
            (Some(cap), Some(certp), Some(keyp)) => {
                let cas = match cap.to_str() {
                    Some(cav) => cav.to_string(),
                    None => {
                        error!("Invalid CA path");
                        std::process::exit(1);
                    }
                };
                let certs = match certp.to_str() {
                    Some(certv) => certv.to_string(),
                    None => {
                        error!("Invalid Cert path");
                        std::process::exit(1);
                    }
                };
                let keys = match keyp.to_str() {
                    Some(keyv) => keyv.to_string(),
                    None => {
                        error!("Invalid Key path");
                        std::process::exit(1);
                    }
                };
                self.tls_config = Some(
                    TlsConfiguration {
                        ca: cas,
                        cert: certs,
                        key: keys,
                    }
                )
            }
            _ => {
                error!("Invalid TLS configuration - must provide ca, cert and key!");
                std::process::exit(1);
            }
        }
    }


}
