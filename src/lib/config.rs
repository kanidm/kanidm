use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct Configuration {
    pub address: String,
    pub domain: String,
    pub threads: usize,
    pub db_path: String,
    pub maximum_request: usize,
    // db type later
    pub secure_cookies: bool,
}

impl Configuration {
    pub fn new() -> Self {
        Configuration {
            address: String::from("127.0.0.1:8080"),
            domain: String::from("127.0.0.1"),
            threads: 8,
            db_path: String::from(""),
            maximum_request: 262144, // 256k
            // log type
            // log path
            // TODO: default true in prd
            secure_cookies: false,
        }
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
