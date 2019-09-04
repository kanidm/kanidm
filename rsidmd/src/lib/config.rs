use rand::prelude::*;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct IntegrationTestConfig {
    pub admin_password: String,
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
    pub cookie_key: [u8; 32],
    pub integration_test_config: Option<Box<IntegrationTestConfig>>,
}

impl Configuration {
    pub fn new() -> Self {
        let mut c = Configuration {
            address: String::from("127.0.0.1:8080"),
            domain: String::from("localhost"),
            threads: 8,
            db_path: String::from(""),
            maximum_request: 262144, // 256k
            // log type
            // log path
            // TODO #63: default true in prd
            secure_cookies: if cfg!(test) { false } else { true },
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
}
