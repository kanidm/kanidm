use uuid::Uuid;

// Re-export as needed
pub mod system_config;
pub use crate::constants::system_config::JSON_SYSTEM_CONFIG_V1;

// Increment this as we add new schema types and values!!!
pub static SYSTEM_INDEX_VERSION: i64 = 3;
// On test builds, define to 60 seconds
#[cfg(test)]
pub static PURGE_TIMEOUT: u64 = 60;
// For production, 1 hour.
#[cfg(not(test))]
pub static PURGE_TIMEOUT: u64 = 3600;
// 5 minute auth session window.
pub static AUTH_SESSION_TIMEOUT: u64 = 300;
pub static PW_MIN_LENGTH: usize = 10;

// Built in group and account ranges.
pub static STR_UUID_ADMIN: &str = "00000000-0000-0000-0000-000000000000";
pub static _UUID_IDM_ADMINS: &str = "00000000-0000-0000-0000-000000000001";
pub static _UUID_IDM_PEOPLE_READ_PRIV: &str = "00000000-0000-0000-0000-000000000002";
pub static _UUID_IDM_PEOPLE_WRITE_PRIV: &str = "00000000-0000-0000-0000-000000000003";
pub static _UUID_IDM_GROUP_WRITE_PRIV: &str = "00000000-0000-0000-0000-000000000004";
pub static _UUID_IDM_ACCOUNT_READ_PRIV: &str = "00000000-0000-0000-0000-000000000005";
pub static _UUID_IDM_ACCOUNT_WRITE_PRIV: &str = "00000000-0000-0000-0000-000000000006";
pub static _UUID_IDM_RADIUS_SERVERS: &str = "00000000-0000-0000-0000-000000000007";
pub static _UUID_IDM_HP_ACCOUNT_READ_PRIV: &str = "00000000-0000-0000-0000-000000000008";
pub static _UUID_IDM_HP_ACCOUNT_WRITE_PRIV: &str = "00000000-0000-0000-0000-000000000009";
pub static _UUID_IDM_SCHEMA_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000010";
pub static _UUID_IDM_ACP_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000011";
pub static _UUID_IDM_HP_GROUP_WRITE_PRIV: &str = "00000000-0000-0000-0000-000000000012";
pub static _UUID_IDM_PEOPLE_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000013";
pub static _UUID_IDM_ACCOUNT_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000014";
pub static _UUID_IDM_GROUP_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000015";
pub static _UUID_IDM_HP_ACCOUNT_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000016";
pub static _UUID_IDM_HP_GROUP_MANAGE_PRIV: &str = "00000000-0000-0000-0000-000000000017";
pub static _UUID_IDM_ADMIN_V1: &str = "00000000-0000-0000-0000-000000000018";
pub static _UUID_SYSTEM_ADMINS: &str = "00000000-0000-0000-0000-000000000019";
// TODO
pub static UUID_DOMAIN_ADMINS: &str = "00000000-0000-0000-0000-000000000020";
pub static _UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV: &str = "00000000-0000-0000-0000-000000000021";
pub static _UUID_IDM_GROUP_UNIX_EXTEND_PRIV: &str = "00000000-0000-0000-0000-000000000022";
//
pub static _UUID_IDM_HIGH_PRIVILEGE: &str = "00000000-0000-0000-0000-000000001000";

// Builtin schema
pub static UUID_SCHEMA_ATTR_CLASS: &str = "00000000-0000-0000-0000-ffff00000000";
pub static UUID_SCHEMA_ATTR_UUID: &str = "00000000-0000-0000-0000-ffff00000001";
pub static UUID_SCHEMA_ATTR_NAME: &str = "00000000-0000-0000-0000-ffff00000002";
pub static UUID_SCHEMA_ATTR_SPN: &str = "00000000-0000-0000-0000-ffff00000003";
pub static UUID_SCHEMA_ATTR_DESCRIPTION: &str = "00000000-0000-0000-0000-ffff00000004";
pub static UUID_SCHEMA_ATTR_MULTIVALUE: &str = "00000000-0000-0000-0000-ffff00000005";
pub static UUID_SCHEMA_ATTR_UNIQUE: &str = "00000000-0000-0000-0000-ffff00000047";
pub static UUID_SCHEMA_ATTR_INDEX: &str = "00000000-0000-0000-0000-ffff00000006";
pub static UUID_SCHEMA_ATTR_SYNTAX: &str = "00000000-0000-0000-0000-ffff00000007";
pub static UUID_SCHEMA_ATTR_SYSTEMMAY: &str = "00000000-0000-0000-0000-ffff00000008";
pub static UUID_SCHEMA_ATTR_MAY: &str = "00000000-0000-0000-0000-ffff00000009";
pub static UUID_SCHEMA_ATTR_SYSTEMMUST: &str = "00000000-0000-0000-0000-ffff00000010";
pub static UUID_SCHEMA_ATTR_MUST: &str = "00000000-0000-0000-0000-ffff00000011";
pub static UUID_SCHEMA_ATTR_MEMBEROF: &str = "00000000-0000-0000-0000-ffff00000012";
pub static UUID_SCHEMA_ATTR_MEMBER: &str = "00000000-0000-0000-0000-ffff00000013";
pub static UUID_SCHEMA_ATTR_DIRECTMEMBEROF: &str = "00000000-0000-0000-0000-ffff00000014";
pub static UUID_SCHEMA_ATTR_VERSION: &str = "00000000-0000-0000-0000-ffff00000015";
pub static UUID_SCHEMA_ATTR_DOMAIN: &str = "00000000-0000-0000-0000-ffff00000016";
pub static UUID_SCHEMA_ATTR_ACP_ENABLE: &str = "00000000-0000-0000-0000-ffff00000017";
pub static UUID_SCHEMA_ATTR_ACP_RECEIVER: &str = "00000000-0000-0000-0000-ffff00000018";
pub static UUID_SCHEMA_ATTR_ACP_TARGETSCOPE: &str = "00000000-0000-0000-0000-ffff00000019";
pub static UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR: &str = "00000000-0000-0000-0000-ffff00000020";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_CLASS: &str = "00000000-0000-0000-0000-ffff00000021";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_ATTR: &str = "00000000-0000-0000-0000-ffff00000022";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR: &str = "00000000-0000-0000-0000-ffff00000023";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR: &str = "00000000-0000-0000-0000-ffff00000024";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS: &str = "00000000-0000-0000-0000-ffff00000025";
pub static UUID_SCHEMA_CLASS_ATTRIBUTETYPE: &str = "00000000-0000-0000-0000-ffff00000026";
pub static UUID_SCHEMA_CLASS_CLASSTYPE: &str = "00000000-0000-0000-0000-ffff00000027";
pub static UUID_SCHEMA_CLASS_OBJECT: &str = "00000000-0000-0000-0000-ffff00000028";
pub static UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT: &str = "00000000-0000-0000-0000-ffff00000029";
pub static UUID_SCHEMA_CLASS_MEMBEROF: &str = "00000000-0000-0000-0000-ffff00000030";
pub static UUID_SCHEMA_CLASS_RECYCLED: &str = "00000000-0000-0000-0000-ffff00000031";
pub static UUID_SCHEMA_CLASS_TOMBSTONE: &str = "00000000-0000-0000-0000-ffff00000032";
pub static UUID_SCHEMA_CLASS_SYSTEM_INFO: &str = "00000000-0000-0000-0000-ffff00000033";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE: &str = "00000000-0000-0000-0000-ffff00000034";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH: &str = "00000000-0000-0000-0000-ffff00000035";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE: &str = "00000000-0000-0000-0000-ffff00000036";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY: &str = "00000000-0000-0000-0000-ffff00000037";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE: &str = "00000000-0000-0000-0000-ffff00000038";
pub static UUID_SCHEMA_CLASS_SYSTEM: &str = "00000000-0000-0000-0000-ffff00000039";
pub static UUID_SCHEMA_ATTR_DISPLAYNAME: &str = "00000000-0000-0000-0000-ffff00000040";
pub static UUID_SCHEMA_ATTR_MAIL: &str = "00000000-0000-0000-0000-ffff00000041";
pub static UUID_SCHEMA_ATTR_SSH_PUBLICKEY: &str = "00000000-0000-0000-0000-ffff00000042";
pub static UUID_SCHEMA_ATTR_PRIMARY_CREDENTIAL: &str = "00000000-0000-0000-0000-ffff00000043";
pub static UUID_SCHEMA_CLASS_PERSON: &str = "00000000-0000-0000-0000-ffff00000044";
pub static UUID_SCHEMA_CLASS_GROUP: &str = "00000000-0000-0000-0000-ffff00000045";
pub static UUID_SCHEMA_CLASS_ACCOUNT: &str = "00000000-0000-0000-0000-ffff00000046";
// GAP - 47
pub static UUID_SCHEMA_ATTR_ATTRIBUTENAME: &str = "00000000-0000-0000-0000-ffff00000048";
pub static UUID_SCHEMA_ATTR_CLASSNAME: &str = "00000000-0000-0000-0000-ffff00000049";
pub static UUID_SCHEMA_ATTR_LEGALNAME: &str = "00000000-0000-0000-0000-ffff00000050";
pub static UUID_SCHEMA_ATTR_RADIUS_SECRET: &str = "00000000-0000-0000-0000-ffff00000051";
pub static UUID_SCHEMA_CLASS_DOMAIN_INFO: &str = "00000000-0000-0000-0000-ffff00000052";
pub static UUID_SCHEMA_ATTR_DOMAIN_NAME: &str = "00000000-0000-0000-0000-ffff00000053";
pub static UUID_SCHEMA_ATTR_DOMAIN_UUID: &str = "00000000-0000-0000-0000-ffff00000054";
pub static UUID_SCHEMA_ATTR_DOMAIN_SSID: &str = "00000000-0000-0000-0000-ffff00000055";

pub static UUID_SCHEMA_ATTR_GIDNUMBER: &str = "00000000-0000-0000-0000-ffff00000056";
pub static UUID_SCHEMA_CLASS_POSIXACCOUNT: &str = "00000000-0000-0000-0000-ffff00000057";
pub static UUID_SCHEMA_CLASS_POSIXGROUP: &str = "00000000-0000-0000-0000-ffff00000058";
pub static UUID_SCHEMA_ATTR_BADLIST_PASSWORD: &str = "00000000-0000-0000-0000-ffff00000059";
pub static UUID_SCHEMA_CLASS_SYSTEM_CONFIG: &str = "00000000-0000-0000-0000-ffff00000060";
pub static UUID_SCHEMA_ATTR_LOGINSHELL: &str = "00000000-0000-0000-0000-ffff00000061";

// System and domain infos
// I'd like to strongly criticise william of the past for fucking up these allocations.
pub static _UUID_SYSTEM_INFO: &str = "00000000-0000-0000-0000-ffffff000001";
pub static UUID_DOMAIN_INFO: &str = "00000000-0000-0000-0000-ffffff000025";
// DO NOT allocate here, allocate below.

// Access controls
// skip 00 / 01 - see system info
pub static _UUID_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: &str = "00000000-0000-0000-0000-ffffff000002";
pub static _UUID_IDM_ADMINS_ACP_REVIVE_V1: &str = "00000000-0000-0000-0000-ffffff000003";
pub static _UUID_IDM_SELF_ACP_READ_V1: &str = "00000000-0000-0000-0000-ffffff000004";
pub static _UUID_IDM_ALL_ACP_READ_V1: &str = "00000000-0000-0000-0000-ffffff000006";
pub static _UUID_IDM_ACP_PEOPLE_READ_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000007";
pub static _UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000008";
pub static _UUID_IDM_ACP_GROUP_WRITE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000009";
pub static _UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000010";
pub static _UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000011";
pub static _UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000012";
pub static _UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000013";
pub static _UUID_IDM_ACP_RADIUS_SERVERS_V1: &str = "00000000-0000-0000-0000-ffffff000014";
pub static _UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000015";
pub static _UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000016";
pub static _UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000017";
pub static _UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000018";
pub static _UUID_IDM_ACP_ACP_MANAGE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000019";
pub static _UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: &str =
    "00000000-0000-0000-0000-ffffff000020";
pub static _UUID_IDM_SELF_ACP_WRITE_V1: &str = "00000000-0000-0000-0000-ffffff000021";
pub static _UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000022";
pub static _UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000023";
pub static _UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000024";
// Skip 25 - see domain info.
pub static UUID_IDM_ACP_DOMAIN_ADMIN_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000026";
pub static STR_UUID_SYSTEM_CONFIG: &str = "00000000-0000-0000-0000-ffffff000027";
pub static UUID_IDM_ACP_SYSTEM_CONFIG_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000028";
pub static _UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000029";
pub static _UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000030";


// End of system ranges
pub static STR_UUID_DOES_NOT_EXIST: &str = "00000000-0000-0000-0000-fffffffffffe";
pub static STR_UUID_ANONYMOUS: &str = "00000000-0000-0000-0000-ffffffffffff";

lazy_static! {
    pub static ref UUID_ADMIN: Uuid = Uuid::parse_str(STR_UUID_ADMIN).unwrap();
    pub static ref UUID_DOES_NOT_EXIST: Uuid = Uuid::parse_str(STR_UUID_DOES_NOT_EXIST).unwrap();
    pub static ref UUID_ANONYMOUS: Uuid = Uuid::parse_str(STR_UUID_ANONYMOUS).unwrap();
    pub static ref UUID_SYSTEM_CONFIG: Uuid = Uuid::parse_str(STR_UUID_SYSTEM_CONFIG).unwrap();
}

pub static JSON_ADMIN_V1: &str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-000000000000"
    },
    "state": null,
    "attrs": {
        "class": ["account", "memberof", "object"],
        "name": ["admin"],
        "uuid": ["00000000-0000-0000-0000-000000000000"],
        "description": ["Builtin System Admin account."],
        "displayname": ["System Administrator"]
    }
}"#;

pub static JSON_IDM_ADMIN_V1: &str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-000000000018"
    },
    "state": null,
    "attrs": {
        "class": ["account", "memberof", "object"],
        "name": ["idm_admin"],
        "uuid": ["00000000-0000-0000-0000-000000000018"],
        "description": ["Builtin IDM Admin account."],
        "displayname": ["IDM Administrator"]
    }
}"#;

pub static JSON_IDM_ADMINS_V1: &str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-000000000001"
    },
    "state": null,
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_admins"],
        "uuid": ["00000000-0000-0000-0000-000000000001"],
        "description": ["Builtin IDM Administrators Group."],
        "member": ["00000000-0000-0000-0000-000000000018"]
    }
}"#;

pub static JSON_SYSTEM_ADMINS_V1: &str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-000000000019"
    },
    "state": null,
    "attrs": {
        "class": ["group", "object"],
        "name": ["system_admins"],
        "uuid": ["00000000-0000-0000-0000-000000000019"],
        "description": ["Builtin System Administrators Group."],
        "member": ["00000000-0000-0000-0000-000000000000"]
    }
}"#;

// groups
// * People read managers
pub static JSON_IDM_PEOPLE_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000002"],
        "description": ["Builtin IDM Group for granting elevated people (personal data) read permissions."],
        "member": ["00000000-0000-0000-0000-000000000003"]
    }
}"#;
// * People write managers
pub static JSON_IDM_PEOPLE_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000013"],
        "description": ["Builtin IDM Group for granting elevated people (personal data) write and lifecycle management permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000001"
        ]
    }
}"#;
pub static JSON_IDM_PEOPLE_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000003"],
        "description": ["Builtin IDM Group for granting elevated people (personal data) write permissions."],
        "member": ["00000000-0000-0000-0000-000000000013"]
    }
}"#;
// * group write manager (no read, everyone has read via the anon, etc)
// IDM_GROUP_CREATE_PRIV
pub static JSON_IDM_GROUP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_group_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000015"],
        "description": ["Builtin IDM Group for granting elevated group write and lifecycle permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;
pub static JSON_IDM_GROUP_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_group_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000004"],
        "description": ["Builtin IDM Group for granting elevated group write permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000015"
        ]
    }
}"#;
pub static JSON_IDM_GROUP_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_group_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000022"],
        "description": ["Builtin IDM Group for granting unix group extension permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000001"
        ]
    }
}"#;
// * account read manager
pub static JSON_IDM_ACCOUNT_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000005"],
        "description": ["Builtin IDM Group for granting elevated account read permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000006"
        ]
    }
}"#;
// * account write manager
pub static JSON_IDM_ACCOUNT_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000014"],
        "description": ["Builtin IDM Group for granting elevated account write and lifecycle permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000001"
        ]
    }
}"#;
pub static JSON_IDM_ACCOUNT_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000006"],
        "description": ["Builtin IDM Group for granting elevated account write permissions."],
        "member": ["00000000-0000-0000-0000-000000000014"]
    }
}"#;
pub static JSON_IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000021"],
        "description": ["Builtin IDM Group for granting account unix extend permissions."],
        "member": ["00000000-0000-0000-0000-000000000001"]
    }
}"#;
// * RADIUS servers
pub static JSON_IDM_RADIUS_SERVERS_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_radius_servers"],
        "uuid": ["00000000-0000-0000-0000-000000000007"],
        "description": ["Builtin IDM Group for RADIUS server access delegation."]
    }
}"#;
// * high priv account read manager
pub static JSON_IDM_HP_ACCOUNT_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_account_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000008"],
        "description": ["Builtin IDM Group for granting elevated account read permissions over high privilege accounts."],
        "member": [
            "00000000-0000-0000-0000-000000000009"
        ]
    }
}"#;
// * high priv account write manager
pub static JSON_IDM_HP_ACCOUNT_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_account_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000016"],
        "description": ["Builtin IDM Group for granting elevated account write and lifecycle permissions over high privilege accounts."],
        "member": [
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;
pub static JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000009"],
        "description": ["Builtin IDM Group for granting elevated account write permissions over high privilege accounts."],
        "member": [
            "00000000-0000-0000-0000-000000000016"
        ]
    }
}"#;
// * Schema write manager
pub static JSON_IDM_SCHEMA_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_schema_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000010"],
        "description": ["Builtin IDM Group for granting elevated schema write and management permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;
// * ACP read/write manager
pub static JSON_IDM_ACP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_acp_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000011"],
        "description": ["Builtin IDM Group for granting control over all access control profile modifications."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;

pub static JSON_IDM_HP_GROUP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_group_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000017"],
        "description": ["Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;
pub static JSON_IDM_HP_GROUP_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_group_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000012"],
        "description": ["Builtin IDM Group for granting elevated group write privileges for high privilege groups."],
        "member": [
            "00000000-0000-0000-0000-000000000017"
        ]
    }
}"#;
pub static JSON_DOMAIN_ADMINS: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["domain_admins"],
        "uuid": ["00000000-0000-0000-0000-000000000020"],
        "description": ["Builtin IDM Group for granting local domain administration rights and trust administration rights."],
        "member": [
            "00000000-0000-0000-0000-000000000000"
        ]
    }
}"#;

// This must be the last group to init to include the UUID of the other high priv groups.
pub static JSON_IDM_HIGH_PRIVILEGE_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_high_privilege"],
        "uuid": ["00000000-0000-0000-0000-000000001000"],
        "description": ["Builtin IDM provided groups with high levels of access that should be audited and limited in modification."],
        "member": [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000004",
            "00000000-0000-0000-0000-000000000005",
            "00000000-0000-0000-0000-000000000006",
            "00000000-0000-0000-0000-000000000007",
            "00000000-0000-0000-0000-000000000008",
            "00000000-0000-0000-0000-000000000009",
            "00000000-0000-0000-0000-000000000010",
            "00000000-0000-0000-0000-000000000011",
            "00000000-0000-0000-0000-000000000012",
            "00000000-0000-0000-0000-000000000013",
            "00000000-0000-0000-0000-000000000014",
            "00000000-0000-0000-0000-000000000015",
            "00000000-0000-0000-0000-000000000016",
            "00000000-0000-0000-0000-000000000017",
            "00000000-0000-0000-0000-000000000019",
            "00000000-0000-0000-0000-000000000020",
            "00000000-0000-0000-0000-000000001000"
        ]
    }
}"#;

pub static JSON_SYSTEM_INFO_V1: &str = r#"{
    "attrs": {
        "class": ["object", "system_info", "system"],
        "uuid": ["00000000-0000-0000-0000-ffffff000001"],
        "description": ["System info and metadata object."],
        "version": ["2"]
    }
}"#;

pub static JSON_DOMAIN_INFO_V1: &str = r#"{
    "attrs": {
        "class": ["object", "domain_info", "system"],
        "name": ["domain_local"],
        "uuid": ["00000000-0000-0000-0000-ffffff000025"],
        "description": ["This local domain's info and metadata object."]
    }
}"#;

/*
// Template acp
pub static _UUID_IDM_ACP_XX_V1: &str = "00000000-0000-0000-0000-ffffff0000XX";
pub static JSON_IDM_ACP_XX_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify",
            "access_control_create",
            "access_control_delete"
        ],
        "name": ["idm_acp_xx"],
        "uuid": ["00000000-0000-0000-0000-ffffff0000XX"],
        "description": ["Builtin IDM Control for xx"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-0000000000XX\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"attr\",\"value\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [

        ],
        "acp_modify_removedattr": [

        ],
        "acp_modify_presentattr": [

        ],
        "acp_modify_class":  [

        ],
        "acp_create_attr": [

        ],
        "acp_create_class": [

        ]
    }
}"#;
*/

pub static JSON_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: &str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_admins_acp_recycle_search"],
        "uuid": ["00000000-0000-0000-0000-ffffff000002"],
        "description": ["Builtin IDM admin recycle bin search permission."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000019\"]}"
        ],
        "acp_targetscope": [
            "{\"Eq\": [\"class\", \"recycled\"]}"
        ],
        "acp_search_attr": ["name", "class", "uuid"]
    }
}"#;

pub static JSON_IDM_ADMINS_ACP_REVIVE_V1: &str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_modify"],
        "name": ["idm_admins_acp_revive"],
        "uuid": ["00000000-0000-0000-0000-ffffff000003"],
        "description": ["Builtin IDM Administrators Access Controls."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000019\"]}"
        ],
        "acp_targetscope": [
            "{\"Eq\":[\"class\",\"recycled\"]}"
        ],
        "acp_modify_removedattr": ["class"],
        "acp_modify_class": ["recycled"]
    }
}"#;

pub static JSON_IDM_SELF_ACP_READ_V1: &str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_self_acp_read"],
        "uuid": ["00000000-0000-0000-0000-ffffff000004"],
        "description": ["Builtin IDM Control for self read - required for whoami and many other functions."],
        "acp_receiver": [
            "{\"And\": [\"Self\", {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_targetscope": [
            "\"Self\""
        ],
        "acp_search_attr": [
            "name",
            "spn",
            "displayname",
            "legalname",
            "class",
            "memberof",
            "radius_secret",
            "gidnumber",
            "loginshell",
            "uuid"
        ]
    }
}"#;

pub static JSON_IDM_SELF_ACP_WRITE_V1: &str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_modify"],
        "name": ["idm_self_acp_write"],
        "uuid": ["00000000-0000-0000-0000-ffffff000021"],
        "description": ["Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices."],
        "acp_receiver": [
            "{\"And\": [\"Self\", {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}, {\"Eq\": [\"uuid\", \"00000000-0000-0000-0000-ffffffffffff\"]}]}}]}"
        ],
        "acp_targetscope": [
            "\"Self\""
        ],
        "acp_modify_removedattr": [
            "name", "displayname", "legalname", "radius_secret", "primary_credential", "ssh_publickey"
        ],
        "acp_modify_presentattr": [
            "name", "displayname", "legalname", "radius_secret", "primary_credential", "ssh_publickey"
        ]
    }
}"#;

pub static JSON_IDM_ALL_ACP_READ_V1: &str = r#"{
    "state": null,
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_all_acp_read"],
        "uuid": ["00000000-0000-0000-0000-ffffff000006"],
        "description": ["Builtin IDM Control for all read - IE anonymous and all authenticated accounts."],
        "acp_receiver": [
            "{\"Pres\":\"class\"}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Pres\": \"class\"}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name",
            "spn",
            "displayname",
            "class",
            "memberof",
            "member",
            "uuid",
            "gidnumber",
            "loginshell",
            "ssh_publickey"
        ]
    }
}"#;

// 7 people read acp JSON_IDM_PEOPLE_READ_PRIV_V1
pub static JSON_IDM_ACP_PEOPLE_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_people_read_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000007"],
        "description": ["Builtin IDM Control for reading personal sensitive data."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000002\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name", "displayname", "legalname", "mail"
        ]
    }
}"#;
// 8 people write acp JSON_IDM_PEOPLE_WRITE_PRIV_V1
pub static JSON_IDM_ACP_PEOPLE_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_people_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000008"],
        "description": ["Builtin IDM Control for managing personal and sensitive data."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000003\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"person\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_modify_removedattr": [
            "name", "displayname", "legalname", "mail"
        ],
        "acp_modify_presentattr": [
            "name", "displayname", "legalname", "mail"
        ]
    }
}"#;
// 9 group write acp JSON_IDM_GROUP_WRITE_PRIV_V1
pub static JSON_IDM_ACP_GROUP_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify"
        ],
        "name": ["idm_acp_group_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000009"],
        "description": ["Builtin IDM Control for managing groups"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000004\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"group\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "spn", "uuid", "description", "member"
        ],
        "acp_modify_removedattr": [
            "name", "description", "member"
        ],
        "acp_modify_presentattr": [
            "name", "description", "member"
        ]
    }
}"#;
// 10 account read acp JSON_IDM_ACCOUNT_READ_PRIV_V1
pub static JSON_IDM_ACP_ACCOUNT_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_account_read_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000010"],
        "description": ["Builtin IDM Control for accounts."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000005\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "spn", "uuid", "displayname", "ssh_publickey", "primary_credential", "memberof", "mail", "gidnumber"
        ]
    }
}"#;
// 11 account write acp JSON_IDM_ACCOUNT_WRITE_PRIV_V1
pub static JSON_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000011"],
        "description": ["Builtin IDM Control for managing accounts."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000006\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_modify_removedattr": [
            "name", "displayname", "ssh_publickey", "primary_credential", "mail"
        ],
        "acp_modify_presentattr": [
            "name", "displayname", "ssh_publickey", "primary_credential", "mail"
        ]
    }
}"#;
// 12 service account create acp (only admins?)  JSON_IDM_SERVICE_ACCOUNT_CREATE_PRIV_V1
pub static JSON_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_delete",
            "access_control_create"
        ],
        "name": ["idm_acp_account_manage"],
        "uuid": ["00000000-0000-0000-0000-ffffff000012"],
        "description": ["Builtin IDM Control for creating and deleting (service) accounts"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000014\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_create_attr": [
            "class",
            "name",
            "displayname",
            "description",
            "primary_credential",
            "ssh_publickey"
        ],
        "acp_create_class": [
            "object", "account"
        ]
    }
}"#;
// 13 user (person) account create acp  JSON_IDM_PERSON_ACCOUNT_CREATE_PRIV_V1
pub static JSON_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_delete",
            "access_control_create"
        ],
        "name": ["idm_acp_people_manage"],
        "uuid": ["00000000-0000-0000-0000-ffffff000013"],
        "description": ["Builtin IDM Control for creating person (user) accounts"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000013\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"Eq\": [\"class\",\"person\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_create_attr": [
            "class",
            "name",
            "displayname",
            "legalname",
            "primary_credential",
            "ssh_publickey",
            "mail"
        ],
        "acp_create_class": [
            "object", "person", "account"
        ]
    }
}"#;

// 14 radius read acp JSON_IDM_RADIUS_SERVERS_V1
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.
pub static JSON_IDM_ACP_RADIUS_SERVERS_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_radius_servers"],
        "uuid": ["00000000-0000-0000-0000-ffffff000014"],
        "description": ["Builtin IDM Control for RADIUS servers to read credentials and other needed details."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000007\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Pres\": \"class\"}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name", "spn", "uuid", "radius_secret"
        ]
    }
}"#;
// 15 high priv account read JSON_IDM_HP_ACCOUNT_READ_PRIV_V1
pub static JSON_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_hp_account_read_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000015"],
        "description": ["Builtin IDM Control for reading high privilege accounts."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000009\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "spn", "uuid", "displayname", "ssh_publickey", "primary_credential", "memberof"
        ]
    }
}"#;
// 16 high priv account write JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1
pub static JSON_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_hp_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000016"],
        "description": ["Builtin IDM Control for managing high privilege accounts."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000009\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_modify_removedattr": [
            "name", "displayname", "ssh_publickey", "primary_credential"
        ],
        "acp_modify_presentattr": [
            "name", "displayname", "ssh_publickey", "primary_credential"
        ]
    }
}"#;

// 17 high priv group write --> JSON_IDM_HP_GROUP_WRITE_PRIV_V1 (12)
pub static JSON_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify"
        ],
        "name": ["idm_acp_hp_group_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000017"],
        "description": ["Builtin IDM Control for managing high privilege groups"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000012\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"group\"]}, {\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "uuid", "description", "member"
        ],
        "acp_modify_removedattr": [
            "name", "description", "member"
        ],
        "acp_modify_presentattr": [
            "name", "description", "member"
        ]
    }
}"#;

// 18 schema write JSON_IDM_SCHEMA_WRITE_PRIV_V1
pub static JSON_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify",
            "access_control_create"
        ],
        "name": ["idm_acp_schema_write_attrs_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000018"],
        "description": ["Builtin IDM Control for management of schema attributes."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000010\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"attributetype\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class",
            "description",
            "index",
            "unique",
            "multivalue",
            "attributename",
            "syntax",
            "uuid"
        ],
        "acp_modify_removedattr": [
            "description",
            "index",
            "unique",
            "multivalue",
            "syntax"
        ],
        "acp_modify_presentattr": [
            "description",
            "index",
            "unique",
            "multivalue",
            "syntax"
        ],
        "acp_modify_class":  [],
        "acp_create_attr": [
            "class",
            "description",
            "index",
            "unique",
            "multivalue",
            "attributename",
            "syntax",
            "uuid"
        ],
        "acp_create_class": [
            "object", "attributetype"
        ]
    }
}"#;

// 19 acp read/write
pub static JSON_IDM_ACP_ACP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify",
            "access_control_create",
            "access_control_delete"
        ],
        "name": ["idm_acp_acp_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000019"],
        "description": ["Builtin IDM Control for access profiles management."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000011\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"access_control_profile\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name",
            "class",
            "description",
            "acp_enable",
            "acp_receiver",
            "acp_targetscope",
            "acp_search_attr",
            "acp_modify_removedattr",
            "acp_modify_presentattr",
            "acp_modify_class",
            "acp_create_class",
            "acp_create_attr"
        ],
        "acp_modify_removedattr": [
            "name",
            "class",
            "description",
            "acp_enable",
            "acp_receiver",
            "acp_targetscope",
            "acp_search_attr",
            "acp_modify_removedattr",
            "acp_modify_presentattr",
            "acp_modify_class",
            "acp_create_class",
            "acp_create_attr"
        ],
        "acp_modify_presentattr": [
            "name",
            "class",
            "description",
            "acp_enable",
            "acp_receiver",
            "acp_targetscope",
            "acp_search_attr",
            "acp_modify_removedattr",
            "acp_modify_presentattr",
            "acp_modify_class",
            "acp_create_class",
            "acp_create_attr"
        ],
        "acp_modify_class":  [
            "access_control_profile",
            "access_control_search",
            "access_control_modify",
            "access_control_create",
            "access_control_delete"
        ],
        "acp_create_attr": [
            "name",
            "class",
            "description",
            "acp_enable",
            "acp_receiver",
            "acp_targetscope",
            "acp_search_attr",
            "acp_modify_removedattr",
            "acp_modify_presentattr",
            "acp_modify_class",
            "acp_create_class",
            "acp_create_attr"
        ],
        "acp_create_class": [
            "access_control_profile",
            "access_control_search",
            "access_control_modify",
            "access_control_create",
            "access_control_delete"
        ]
    }
}"#;

pub static JSON_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify",
            "access_control_create"
        ],
        "name": ["idm_acp_schema_write_classes_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000020"],
        "description": ["Builtin IDM Control for management of schema classes."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000010\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"classtype\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class",
            "description",
            "classname",
            "systemmay",
            "may",
            "systemmust",
            "must",
            "uuid"
        ],
        "acp_modify_removedattr": [
            "class",
            "description",
            "may",
            "must"
        ],
        "acp_modify_presentattr": [
            "class",
            "description",
            "may",
            "must"
        ],
        "acp_modify_class":  [],
        "acp_create_attr": [
            "class",
            "description",
            "classname",
            "may",
            "must",
            "uuid"
        ],
        "acp_create_class": [
            "object", "classtype"
        ]
    }
}"#;

// 21 - anonymous / everyone schema read.

// 22 - group create right
pub static JSON_IDM_ACP_GROUP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_delete",
            "access_control_create"
        ],
        "name": ["idm_acp_group_manage"],
        "uuid": ["00000000-0000-0000-0000-ffffff000022"],
        "description": ["Builtin IDM Control for creating and deleting groups in the directory"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000015\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"group\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_create_attr": [
            "class",
            "name",
            "description",
            "member"
        ],
        "acp_create_class": [
            "object", "group"
        ]
    }
}"#;

// 23 - HP account manage
pub static JSON_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_delete",
            "access_control_create"
        ],
        "name": ["idm_acp_hp_account_manage"],
        "uuid": ["00000000-0000-0000-0000-ffffff000023"],
        "description": ["Builtin IDM Control for creating and deleting hp and regular (service) accounts"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000016\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_create_attr": [
            "class",
            "name",
            "displayname",
            "description",
            "primary_credential",
            "ssh_publickey"
        ],
        "acp_create_class": [
            "object", "account"
        ]
    }
}"#;

// 24 - hp group manage
pub static JSON_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_delete",
            "access_control_create"
        ],
        "name": ["idm_acp_hp_group_manage"],
        "uuid": ["00000000-0000-0000-0000-ffffff000024"],
        "description": ["Builtin IDM Control for creating and deleting hp and regular groups in the directory"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000017\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"group\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_create_attr": [
            "class",
            "name",
            "description",
            "member"
        ],
        "acp_create_class": [
            "object", "group"
        ]
    }
}"#;

// 28 - domain admins acp
pub static JSON_IDM_ACP_DOMAIN_ADMIN_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify"
        ],
        "name": ["idm_acp_domain_admin_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000026"],
        "description": ["Builtin IDM Control for granting domain info administration locally"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000020\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000025\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name",
            "uuid",
            "domain_name",
            "domain_ssid",
            "domain_uuid"
        ],
        "acp_modify_removedattr": [
            "domain_ssid"
        ],
        "acp_modify_presentattr": [
            "domain_ssid"
        ]
    }
}"#;

// 28 - system config
pub static JSON_IDM_ACP_SYSTEM_CONFIG_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify"
        ],
        "name": ["idm_acp_system_config_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000028"],
        "description": ["Builtin IDM Control for granting system configuration rights"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000019\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name",
            "uuid",
            "description",
            "badlist_password"
        ],
        "acp_modify_presentattr": [
            "badlist_password"
        ]
    }
}"#;

// 29 account unix extend
pub static JSON_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_search",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_account_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000029"],
        "description": ["Builtin IDM Control for managing accounts."],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000021\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "spn", "uuid", "description", "gidnumber", "loginshell"
        ],
        "acp_modify_removedattr": [
            "class", "loginshell", "gidnumber"
        ],
        "acp_modify_presentattr": [
            "class", "loginshell", "gidnumber"
        ],
        "acp_modify_class": ["posixaccount"]
    }
}"#;
// 30 group unix extend
pub static JSON_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search",
            "access_control_modify"
        ],
        "name": ["idm_acp_group_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000030"],
        "description": ["Builtin IDM Control for managing and extending unix groups"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000022\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"group\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "spn", "uuid", "description", "member", "gidnumber"
        ],
        "acp_modify_removedattr": [
            "class", "gidnumber"
        ],
        "acp_modify_presentattr": [
            "class", "gidnumber"
        ],
        "acp_modify_class": ["posixgroup"]
    }
}"#;

// Anonymous should be the last opbject in the range here.
pub static JSON_ANONYMOUS_V1: &str = r#"{
    "attrs": {
        "class": ["account", "object"],
        "name": ["anonymous"],
        "uuid": ["00000000-0000-0000-0000-ffffffffffff"],
        "description": ["Anonymous access account."],
        "displayname": ["Anonymous"]
    }
}"#;

// Core
// Schema uuids start at 00000000-0000-0000-0000-ffff00000000

// system supplementary
pub static JSON_SCHEMA_ATTR_DISPLAYNAME: &str = r#"{
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000040"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The publicly visible display name of this person"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "displayname"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000040"
      ]
    }
}"#;
pub static JSON_SCHEMA_ATTR_MAIL: &str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000041"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "mail addresses of the object"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "mail"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000041"
      ]
    }
  }
"#;
pub static JSON_SCHEMA_ATTR_SSH_PUBLICKEY: &str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000042"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "SSH public keys of the object"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "ssh_publickey"
      ],
      "syntax": [
        "SSHKEY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000042"
      ]
    }
  }
"#;
pub static JSON_SCHEMA_ATTR_PRIMARY_CREDENTIAL: &str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000043"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "Primary credential material of the account for authentication interactively."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "primary_credential"
      ],
      "syntax": [
        "CREDENTIAL"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000043"
      ]
    }
  }
"#;
pub static JSON_SCHEMA_ATTR_LEGALNAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The private and sensitive legal name of this person"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "legalname"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000050"
      ]
    }
}"#;
pub static JSON_SCHEMA_ATTR_RADIUS_SECRET: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The accounts generated radius secret for device network authentication"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "radius_secret"
      ],
      "syntax": [
        "RADIUS_UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000051"
      ]
    }
}"#;

pub static JSON_SCHEMA_ATTR_DOMAIN_NAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domain's DNS name for webauthn and SPN generation purposes."
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_name"
      ],
      "syntax": [
        "UTF8STRING_INSENSITIVE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000053"
      ]
    }
}"#;
pub static JSON_SCHEMA_ATTR_DOMAIN_UUID: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domain's uuid, used in CSN and trust relationships."
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_uuid"
      ],
      "syntax": [
        "UUID"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000054"
      ]
    }
}"#;
pub static JSON_SCHEMA_ATTR_DOMAIN_SSID: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domains site-wide SSID for device autoconfiguration of wireless"
      ],
      "index": [],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_ssid"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000055"
      ]
    }
}"#;

pub static JSON_SCHEMA_ATTR_GIDNUMBER: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The groupid (uid) number of a group or account. This is the same value as the UID number on posix accounts for security reasons."
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "gidnumber"
      ],
      "syntax": [
        "UINT32"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000056"
      ]
    }
}"#;

pub static JSON_SCHEMA_ATTR_BADLIST_PASSWORD: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A password that is badlisted meaning that it can not be set as a valid password by any user account."
      ],
      "index": [],
      "unique": [
        "true"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "badlist_password"
      ],
      "syntax": [
        "UTF8STRING_INSENSITIVE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000059"
      ]
    }
}"#;

pub static JSON_SCHEMA_ATTR_LOGINSHELL: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A posix users unix login shell"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "loginshell"
      ],
      "syntax": [
        "UTF8STRING_INSENSITIVE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000061"
      ]
    }
}"#;

pub static JSON_SCHEMA_CLASS_PERSON: &str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000044"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a person"
      ],
      "classname": [
        "person"
      ],
      "systemmay": [
        "mail",
        "legalname"
      ],
      "systemmust": [
        "displayname",
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000044"
      ]
    }
  }
"#;

pub static JSON_SCHEMA_CLASS_GROUP: &str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000045"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a group"
      ],
      "classname": [
        "group"
      ],
      "systemmay": [
        "member"
      ],
      "systemmust": [
        "name",
        "spn"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000045"
      ]
    }
  }
"#;
pub static JSON_SCHEMA_CLASS_ACCOUNT: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a account"
      ],
      "classname": [
        "account"
      ],
      "systemmay": [
        "primary_credential",
        "ssh_publickey",
        "radius_secret"
      ],
      "systemmust": [
        "displayname",
        "name",
        "spn"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000046"
      ]
    }
  }
"#;

// domain_info type
//  domain_uuid
//  domain_name <- should be the dns name?
//  domain_ssid <- for radius
//
pub static JSON_SCHEMA_CLASS_DOMAIN_INFO: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Local domain information and partial configuration."
      ],
      "classname": [
        "domain_info"
      ],
      "systemmay": [
        "domain_ssid"
      ],
      "systemmust": [
        "name",
        "domain_uuid",
        "domain_name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000052"
      ]
    }
  }
"#;

pub static JSON_SCHEMA_CLASS_POSIXGROUP: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a posix group, requires group"
      ],
      "classname": [
        "posixgroup"
      ],
      "systemmust": [
        "gidnumber"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000058"
      ]
    }
  }
"#;

pub static JSON_SCHEMA_CLASS_POSIXACCOUNT: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a posix account, requires account"
      ],
      "classname": [
        "posixaccount"
      ],
      "systemmay": [
        "loginshell"
      ],
      "systemmust": [
        "gidnumber"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000057"
      ]
    }
  }
"#;

pub static JSON_SCHEMA_CLASS_SYSTEM_CONFIG: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "The class representing a system (topologies) configuration options."
      ],
      "classname": [
        "system_config"
      ],
      "systemmay": [
        "description",
        "badlist_password"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000060"
      ]
    }
  }
"#;

// need a domain_trust_info as well.
// TODO

// ============ TEST DATA ============
#[cfg(test)]
pub static JSON_TESTPERSON1: &str = r#"{
    "valid": null,
    "state": null,
    "attrs": {
        "class": ["object"],
        "name": ["testperson1"],
        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
    }
}"#;

#[cfg(test)]
pub static JSON_TESTPERSON2: &str = r#"{
    "valid": null,
    "state": null,
    "attrs": {
        "class": ["object"],
        "name": ["testperson2"],
        "uuid": ["538faac7-4d29-473b-a59d-23023ac19955"]
    }
}"#;
