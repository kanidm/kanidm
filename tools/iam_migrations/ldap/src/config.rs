use serde::Deserialize;
use std::collections::BTreeMap;
use url::Url;
use uuid::Uuid;

use ldap3_client::proto::LdapFilter;

fn person_objectclass() -> String {
    "person".to_string()
}

fn person_attr_user_name() -> String {
    "uid".to_string()
}

fn person_attr_display_name() -> String {
    "cn".to_string()
}

fn person_attr_gidnumber() -> String {
    "uidnumber".to_string()
}

fn person_attr_password() -> String {
    "userpassword".to_string()
}

fn person_attr_login_shell() -> String {
    "loginshell".to_string()
}

fn person_attr_mail() -> String {
    "mail".to_string()
}

fn person_attr_ssh_public_key() -> String {
    "sshpublickey".to_string()
}

fn group_objectclass() -> String {
    "groupofnames".to_string()
}

fn group_attr_name() -> String {
    "cn".to_string()
}

fn group_attr_description() -> String {
    "description".to_string()
}

fn group_attr_member() -> String {
    "member".to_string()
}

fn group_attr_gidnumber() -> String {
    "gidnumber".to_string()
}

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

    #[serde(default = "person_objectclass")]
    pub person_objectclass: String,
    #[serde(default = "person_attr_user_name")]
    pub person_attr_user_name: String,
    #[serde(default = "person_attr_display_name")]
    pub person_attr_display_name: String,
    #[serde(default = "person_attr_gidnumber")]
    pub person_attr_gidnumber: String,
    #[serde(default = "person_attr_password")]
    pub person_attr_password: String,
    pub person_password_prefix: Option<String>,
    #[serde(default = "person_attr_login_shell")]
    pub person_attr_login_shell: String,
    #[serde(default = "person_attr_mail")]
    pub person_attr_mail: String,
    #[serde(default = "person_attr_ssh_public_key")]
    pub person_attr_ssh_public_key: String,

    #[serde(default = "group_objectclass")]
    pub group_objectclass: String,
    #[serde(default = "group_attr_name")]
    pub group_attr_name: String,
    #[serde(default = "group_attr_description")]
    pub group_attr_description: String,
    #[serde(default = "group_attr_gidnumber")]
    pub group_attr_gidnumber: String,
    #[serde(default = "group_attr_member")]
    pub group_attr_member: String,

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
