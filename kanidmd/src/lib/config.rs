use rand::prelude::*;
use std::fmt;

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
    pub ldapaddress: Option<String>,
    pub threads: usize,
    // db type later
    pub db_path: String,
    pub db_fs_type: Option<String>,
    pub maximum_request: usize,
    pub secure_cookies: bool,
    pub tls_config: Option<TlsConfiguration>,
    pub cookie_key: [u8; 32],
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
    pub log_level: Option<u32>,
    pub origin: String,
}

impl fmt::Display for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "address: {}, ", self.address)
            .and_then(|_| match &self.ldapaddress {
                Some(la) => write!(f, "ldap address: {}, ", la),
                None => write!(f, "ldap address: disabled, "),
            })
            .and_then(|_| write!(f, "thread count: {}, ", self.threads))
            .and_then(|_| write!(f, "dbpath: {}, ", self.db_path))
            .and_then(|_| write!(f, "max request size: {}b, ", self.maximum_request))
            .and_then(|_| write!(f, "secure cookies: {}, ", self.secure_cookies))
            .and_then(|_| write!(f, "with TLS: {}, ", self.tls_config.is_some()))
            .and_then(|_| match self.log_level {
                Some(u) => write!(f, "with log_level: {:x}, ", u),
                None => write!(f, "with log_level: default, "),
            })
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
            ldapaddress: None,
            threads: num_cpus::get(),
            db_path: String::from(""),
            db_fs_type: None,
            maximum_request: 262_144, // 256k
            // log type
            // log path
            // TODO #63: default true in prd
            secure_cookies: !cfg!(test),
            tls_config: None,
            cookie_key: [0; 32],
            integration_test_config: None,
            log_level: None,
            origin: "https://idm.example.com".to_string(),
        };
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut c.cookie_key);
        c
    }

    pub fn update_log_level(&mut self, log_level: Option<u32>) {
        self.log_level = log_level;
    }

    pub fn update_db_path(&mut self, p: &str) {
        self.db_path = p.to_string();
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

    pub fn update_tls(&mut self, ca: &Option<String>, cert: &Option<String>, key: &Option<String>) {
        match (ca, cert, key) {
            (None, None, None) => {}
            (Some(cap), Some(certp), Some(keyp)) => {
                let cas = cap.to_string();
                let certs = certp.to_string();
                let keys = keyp.to_string();
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
