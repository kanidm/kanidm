use serde::Deserialize;
use std::collections::HashMap;
use url::Url;
use uuid::Uuid;

use ldap3_client::proto::LdapFilter;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub sync_token: String,
    pub schedule: Option<String>,
    pub status_bind: Option<String>,
    pub ldap_uri: Url,
    pub ldap_ca: String,
    pub ldap_sync_dn: String,
    pub ldap_sync_pw: String,
    pub ldap_sync_base_dn: String,

    pub ldap_filter: LdapFilter,

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
