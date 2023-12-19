use serde::Deserialize;
use std::collections::BTreeMap;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub sync_token: String,
    pub schedule: Option<String>,
    pub status_bind: Option<String>,
    pub ipa_uri: Url,
    pub ipa_ca: String,
    pub ipa_sync_dn: String,
    pub ipa_sync_pw: String,
    pub ipa_sync_base_dn: String,

    pub sync_password_as_unix_password: Option<bool>,

    // pub entry: Option<Vec<EntryConfig>>,
    #[serde(flatten)]
    pub entry_map: BTreeMap<Uuid, EntryConfig>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct EntryConfig {
    // Default false
    #[serde(default)]
    pub exclude: bool,

    pub map_uuid: Option<Uuid>,
    pub map_name: Option<String>,
    pub map_gidnumber: Option<u32>,
}
