use kanidm_proto::constants::{DEFAULT_LDAP_LOCALHOST, DEFAULT_SERVER_LOCALHOST};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DsConfig {
    pub uri: String,
    pub dm_pw: String,
    pub base_dn: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpaConfig {
    pub uri: String,
    pub realm: String,
    pub idm_admin_pw: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KaniHttpConfig {
    pub uri: String,
    pub idm_admin_pw: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KaniLdapConfig {
    pub uri: String,
    pub ldap_uri: String,
    pub idm_admin_pw: String,
    pub base_dn: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub data: String,
    pub results: String,
    pub ds_config: Option<DsConfig>,
    pub ipa_config: Option<IpaConfig>,
    pub kani_http_config: Option<KaniHttpConfig>,
    pub kani_ldap_config: Option<KaniLdapConfig>,
    #[serde(default)]
    pub search_basic_config: SearchBasicConfig,
}

impl Default for Profile {
    fn default() -> Self {
        let kani_http_config = KaniHttpConfig {
            uri: format!("https://{}", DEFAULT_SERVER_LOCALHOST),
            idm_admin_pw: "".to_string(),
        };

        let kani_ldap_config = KaniLdapConfig {
            uri: format!("https://{}", DEFAULT_SERVER_LOCALHOST),
            ldap_uri: format!("ldaps://{}", DEFAULT_LDAP_LOCALHOST),
            idm_admin_pw: "".to_string(),
            base_dn: "dn=localhost".to_string(),
        };

        Self {
            name: "orca default profile".to_string(),
            data: "/tmp/kanidm/orcatest".to_string(),
            results: "/tmp/kanidm/orca-results/".to_string(),
            ds_config: None,
            ipa_config: None,
            kani_http_config: Some(kani_http_config),
            kani_ldap_config: Some(kani_ldap_config),
            search_basic_config: SearchBasicConfig::default(),
        }
    }
}
