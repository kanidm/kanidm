use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub sync_token: String,
    pub ipa_uri: Url,
    pub ipa_ca: String,
    pub ipa_sync_dn: String,
    pub ipa_sync_pw: String,
    pub ipa_sync_base_dn: String,
}
