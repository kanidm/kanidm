use lettre::address::Address;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub token: String,
    pub schedule: Option<String>,

    pub instance_display_name: String,
    pub instance_url: Url,

    pub mail_from_address: Address,
    pub mail_reply_to_address: Address,
    pub mail_relay: String,
    pub mail_username: String,
    pub mail_password: String,
}
