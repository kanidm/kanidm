use lettre::address::Address;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub token: String,
    pub schedule: Option<String>,
    // pub status_bind: Option<String>,
    pub mail_from_address: Address,
    pub mail_reply_to_address: Address,
    pub mail_from_display_name: String,
    pub mail_relay: String,
    pub mail_username: String,
    pub mail_password: String,
}
