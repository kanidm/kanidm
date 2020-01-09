use num_cpus;
use rand::prelude::*;
use std::fmt;
use std::path::PathBuf;

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

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Configuration {
    pub address: String,
    pub threads: usize,
    // db type later
    pub db_path: String,
    pub maximum_request: usize,
    pub secure_cookies: bool,
    pub tls_config: Option<TlsConfiguration>,
    pub cookie_key: [u8; 32],
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
}

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {}, ", self.address)
            .and_then(|_| write!(f, "thread count: {}, ", self.threads))
            .and_then(|_| write!(f, "dbpath: {}, ", self.db_path))
            .and_then(|_| write!(f, "max request size: {}b, ", self.maximum_request))
            .and_then(|_| write!(f, "secure cookies: {}, ", self.secure_cookies))
            .and_then(|_| write!(f, "with TLS: {}, ", self.tls_config.is_some()))
            .and_then(|_| {
                write!(
                    f,
                    "integration mode: {}",
                    self.integration_test_config.is_some()
                )
            })
    }
}

impl Configuration {
    pub fn new() -> Self {
        let mut c = Configuration {
            address: String::from("127.0.0.1:8080"),
            threads: num_cpus::get(),
            db_path: String::from(""),
            maximum_request: 262_144, // 256k
            // log type
            // log path
            // TODO #63: default true in prd
            secure_cookies: !cfg!(test),
            tls_config: None,
            cookie_key: [0; 32],
            integration_test_config: None,
        };
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut c.cookie_key);
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

    pub fn update_bind(&mut self, b: &Option<String>) {
        self.address = b
            .as_ref()
            .cloned()
            .unwrap_or_else(|| String::from("127.0.0.1:8080"));
    }

    pub fn update_tls(
        &mut self,
        ca: &Option<PathBuf>,
        cert: &Option<PathBuf>,
        key: &Option<PathBuf>,
    ) {
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
                self.tls_config = Some(TlsConfiguration {
                    ca: cas,
                    cert: certs,
                    key: keys,
                })
            }
            _ => {
                error!("Invalid TLS configuration - must provide ca, cert and key!");
                std::process::exit(1);
            }
        }
    }
}
