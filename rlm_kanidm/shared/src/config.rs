use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RadiusGroupConfig {
    pub spn: String,
    pub vlan: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RadiusClientConfig {
    pub name: String,
    pub ipaddr: String,
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KanidmRadiusConfig {
    pub uri: String,
    pub auth_token: String,
    #[serde(default = "default_bool_true")]
    pub verify_hostnames: bool,
    #[serde(default = "default_bool_true")]
    pub verify_certificate: bool,

    #[serde(default)]
    pub ca_path: Option<String>,

    #[serde(default)]
    pub radius_required_groups: Vec<String>,
    #[serde(default = "default_vlan")]
    /// Defaults to 1, which is the default VLAN for "no VLAN" in many RADIUS setups, but can be set to 0 if the setup expects that for "no VLAN". Any user in a group that doesn't have a specific VLAN mapping will get this VLAN.
    pub radius_default_vlan: u32,
    #[serde(default)]
    pub radius_groups: Vec<RadiusGroupConfig>,
    #[serde(default)]
    pub radius_clients: Vec<RadiusClientConfig>,
    #[serde(default = "default_radius_cert_path")]
    pub radius_cert_path: String,
    #[serde(default = "default_radius_key_path")]
    pub radius_key_path: String,
    #[serde(default)]
    pub radius_ca_path: Option<String>,
    #[serde(default)]
    pub radius_ca_dir: Option<String>,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

impl Default for KanidmRadiusConfig {
    fn default() -> Self {
        Self {
            uri: String::new(),
            auth_token: String::new(),
            verify_hostnames: default_bool_true(),
            verify_certificate: default_bool_true(),
            ca_path: None,
            radius_required_groups: Vec::new(),
            radius_default_vlan: default_vlan(),
            radius_groups: Vec::new(),
            radius_clients: Vec::new(),
            radius_cert_path: default_radius_cert_path(),
            radius_key_path: default_radius_key_path(),
            radius_ca_path: None,
            radius_ca_dir: None,
            connect_timeout_secs: default_connect_timeout_secs(),
        }
    }
}

fn default_bool_true() -> bool {
    true
}

fn default_vlan() -> u32 {
    1
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_radius_cert_path() -> String {
    "/data/cert.pem".to_string()
}

fn default_radius_key_path() -> String {
    "/data/key.pem".to_string()
}
