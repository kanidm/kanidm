#![deny(warnings)]
#![warn(unused_extern_crates)]

use reqwest;

pub struct RsidmClient {
    client: reqwest::Client,
    addr: String,
}

impl RsidmClient {
    pub fn new(addr: &str) -> Self {
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("Unexpected reqwest builder failure!");
        RsidmClient {
            client: client,
            addr: addr.to_string(),
        }
    }

    // auth
    // whoami
    // search
    // create
    // modify
    //
}
