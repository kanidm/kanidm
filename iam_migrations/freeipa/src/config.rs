use serde::Deserialize;
use url::Url;
use uuid::Uuid;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub sync_token: String,
    pub ipa_uri: Url,
    pub ipa_ca: String,
    pub ipa_sync_dn: String,
    pub ipa_sync_pw: String,
    pub ipa_sync_base_dn: String,

    // pub entry: Option<Vec<EntryConfig>>,
    #[serde(flatten)]
    pub entry_map: HashMap<Uuid, EntryConfig>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct EntryConfig {
    // uuid: Uuid,

    // Default false
    #[serde(default)]
    pub exclude: bool,

    // map_uuid: Option<Uuid>,
    // map_external_id: Option<String>,
    // map_name: Option<String>,
}


