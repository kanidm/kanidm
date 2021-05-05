#[derive(Debug, Deserialize)]
pub struct DsConfig {
    pub uri: String,
    pub dm_pw: String,
}

#[derive(Debug, Deserialize)]
pub struct KaniHttpConfig {
    pub uri: String,
    pub admin_pw: String,
}

#[derive(Debug, Deserialize)]
pub struct KaniLdapConfig {
    pub uri: String,
    pub ldap_uri: String,
    pub admin_pw: String,
}

#[derive(Debug, Deserialize)]
pub struct SearchBasicConfig {
    // Could consider fn for this #[serde(default = "Priority::lowest")]
    pub warmup_seconds: u32,
    pub workers: u32,
}

impl Default for SearchBasicConfig {
    fn default() -> Self {
        SearchBasicConfig {
            warmup_seconds: 5,
            workers: 16,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub name: String,
    pub data: String,
    pub results: String,
    pub ds_config: Option<DsConfig>,
    pub kani_http_config: Option<KaniHttpConfig>,
    pub kani_ldap_config: Option<KaniLdapConfig>,
    #[serde(default)]
    pub search_basic_config: SearchBasicConfig,
}
