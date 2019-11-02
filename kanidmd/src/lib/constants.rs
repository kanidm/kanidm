use uuid::Uuid;

// On test builds, define to 60 seconds
#[cfg(test)]
pub static PURGE_TIMEOUT: u64 = 60;
// For production, 1 hour.
#[cfg(not(test))]
pub static PURGE_TIMEOUT: u64 = 3600;
// 5 minute auth session window.
pub static AUTH_SESSION_TIMEOUT: u64 = 300;

pub static STR_UUID_ADMIN: &'static str = "00000000-0000-0000-0000-000000000000";
pub static STR_UUID_ANONYMOUS: &'static str = "00000000-0000-0000-0000-ffffffffffff";
pub static STR_UUID_DOES_NOT_EXIST: &'static str = "00000000-0000-0000-0000-fffffffffffe";
lazy_static! {
    pub static ref UUID_ADMIN: Uuid = Uuid::parse_str(STR_UUID_ADMIN).unwrap();
    pub static ref UUID_DOES_NOT_EXIST: Uuid = Uuid::parse_str(STR_UUID_DOES_NOT_EXIST).unwrap();
    pub static ref UUID_ANONYMOUS: Uuid = Uuid::parse_str(STR_UUID_ANONYMOUS).unwrap();
}

pub static JSON_ADMIN_V1: &'static str = r#"{
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

pub static JSON_IDM_ADMIN_V1: &'static str = r#"{
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

pub static _UUID_IDM_ADMINS: &'static str = "00000000-0000-0000-0000-000000000001";
pub static JSON_IDM_ADMINS_V1: &'static str = r#"{
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

pub static _UUID_SYSTEM_ADMINS: &'static str = "00000000-0000-0000-0000-000000000019";
pub static JSON_SYSTEM_ADMINS_V1: &'static str = r#"{
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
pub static _UUID_IDM_PEOPLE_READ_PRIV: &'static str = "00000000-0000-0000-0000-000000000002";
pub static JSON_IDM_PEOPLE_READ_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000002"],
        "description": ["Builtin IDM Group for granting elevated people (personal data) read permissions."],
        "member": ["00000000-0000-0000-0000-000000000003"]
    }
}"#;
// * People write managers
pub static _UUID_IDM_PEOPLE_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000013";
pub static JSON_IDM_PEOPLE_MANAGE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_PEOPLE_WRITE_PRIV: &'static str = "00000000-0000-0000-0000-000000000003";
pub static JSON_IDM_PEOPLE_WRITE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_GROUP_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000015";
pub static JSON_IDM_GROUP_MANAGE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_GROUP_WRITE_PRIV: &'static str = "00000000-0000-0000-0000-000000000004";
pub static JSON_IDM_GROUP_WRITE_PRIV_V1: &'static str = r#"{
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
// * account read manager
pub static _UUID_IDM_ACCOUNT_READ_PRIV: &'static str = "00000000-0000-0000-0000-000000000005";
pub static JSON_IDM_ACCOUNT_READ_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_ACCOUNT_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000014";
pub static JSON_IDM_ACCOUNT_MANAGE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_ACCOUNT_WRITE_PRIV: &'static str = "00000000-0000-0000-0000-000000000006";
pub static JSON_IDM_ACCOUNT_WRITE_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000006"],
        "description": ["Builtin IDM Group for granting elevated account write permissions."],
        "member": ["00000000-0000-0000-0000-000000000014"]
    }
}"#;
// * RADIUS servers
pub static _UUID_IDM_RADIUS_SERVERS: &'static str = "00000000-0000-0000-0000-000000000007";
pub static JSON_IDM_RADIUS_SERVERS_V1: &'static str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_radius_servers"],
        "uuid": ["00000000-0000-0000-0000-000000000007"],
        "description": ["Builtin IDM Group for RADIUS server access delegation."]
    }
}"#;
// * high priv account read manager
pub static _UUID_IDM_HP_ACCOUNT_READ_PRIV: &'static str = "00000000-0000-0000-0000-000000000008";
pub static JSON_IDM_HP_ACCOUNT_READ_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_HP_ACCOUNT_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000016";
pub static JSON_IDM_HP_ACCOUNT_MANAGE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_HP_ACCOUNT_WRITE_PRIV: &'static str = "00000000-0000-0000-0000-000000000009";
pub static JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_SCHEMA_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000010";
pub static JSON_IDM_SCHEMA_MANAGE_PRIV_V1: &'static str = r#"{
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
pub static _UUID_IDM_ACP_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000011";
pub static JSON_IDM_ACP_MANAGE_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_acp_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000011"],
        "description": ["Builtin IDM Group for granting control over all access control profile modifications."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;

pub static _UUID_IDM_HP_GROUP_MANAGE_PRIV: &'static str = "00000000-0000-0000-0000-000000000017";
pub static JSON_IDM_HP_GROUP_MANAGE_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_group_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000017"],
        "description": ["Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;
pub static _UUID_IDM_HP_GROUP_WRITE_PRIV: &'static str = "00000000-0000-0000-0000-000000000009";
pub static JSON_IDM_HP_GROUP_WRITE_PRIV_V1: &'static str = r#"{
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

// This must be the last group to init to include the UUID of the other high priv groups.
pub static _UUID_IDM_HIGH_PRIVILEGE: &'static str = "00000000-0000-0000-0000-000000001000";
pub static JSON_IDM_HIGH_PRIVILEGE_V1: &'static str = r#"{
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
            "00000000-0000-0000-0000-000000001000"
        ]
    }
}"#;

pub static _UUID_SYSTEM_INFO: &'static str = "00000000-0000-0000-0000-ffffff000001";
pub static JSON_SYSTEM_INFO_V1: &'static str = r#"{
    "attrs": {
        "class": ["object", "system_info"],
        "uuid": ["00000000-0000-0000-0000-ffffff000001"],
        "description": ["System info and metadata object."],
        "version": ["1"],
        "domain": ["example.com"]
    }
}"#;

/*
// Template acp
pub static _UUID_IDM_ACP_XX_V1: &'static str = "00000000-0000-0000-0000-ffffff0000XX";
pub static JSON_IDM_ACP_XX_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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

pub static _UUID_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000002";
pub static JSON_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: &'static str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_admins_acp_recycle_search"],
        "uuid": ["00000000-0000-0000-0000-ffffff000002"],
        "description": ["Builtin IDM admin recycle bin search permission."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000019\"]}"
        ],
        "acp_targetscope": [
            "{\"Eq\": [\"class\", \"recycled\"]}"
        ],
        "acp_search_attr": ["name", "class", "uuid"]
    }
}"#;

pub static _UUID_IDM_ADMINS_ACP_REVIVE_V1: &'static str = "00000000-0000-0000-0000-ffffff000003";
pub static JSON_IDM_ADMINS_ACP_REVIVE_V1: &'static str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_modify"],
        "name": ["idm_admins_acp_revive"],
        "uuid": ["00000000-0000-0000-0000-ffffff000003"],
        "description": ["Builtin IDM Administrators Access Controls."],
        "acp_enable": ["true"],
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

pub static _UUID_IDM_SELF_ACP_READ_V1: &'static str = "00000000-0000-0000-0000-ffffff000004";
pub static JSON_IDM_SELF_ACP_READ_V1: &'static str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_self_acp_read"],
        "uuid": ["00000000-0000-0000-0000-ffffff000004"],
        "description": ["Builtin IDM Control for self read - required for whoami and many other functions."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"And\": [\"Self\", {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_targetscope": [
            "\"Self\""
        ],
        "acp_search_attr": [
            "name",
            "displayname",
            "legalname",
            "class",
            "memberof",
            "member",
            "radius_secret",
            "uuid"
        ]
    }
}"#;

pub static _UUID_IDM_SELF_ACP_WRITE_V1: &'static str = "00000000-0000-0000-0000-ffffff000021";
pub static JSON_IDM_SELF_ACP_WRITE_V1: &'static str = r#"{
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_modify"],
        "name": ["idm_self_acp_write"],
        "uuid": ["00000000-0000-0000-0000-ffffff000021"],
        "description": ["Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"And\": [\"Self\", {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}, {\"Eq\": [\"uuid\", \"00000000-0000-0000-0000-ffffffffffff\"]}]}}]}"
        ],
        "acp_targetscope": [
            "\"Self\""
        ],
        "acp_modify_removedattr": [
            "name", "displayname", "legalname", "radius_secret", "primary_credential"
        ],
        "acp_modify_presentattr": [
            "name", "displayname", "legalname", "radius_secret", "primary_credential"
        ]
    }
}"#;

/*
pub static _UUID_IDM_ADMINS_ACP_MANAGE_V1: &'static str = "00000000-0000-0000-0000-ffffff000005";
pub static JSON_IDM_ADMINS_ACP_MANAGE_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify",
            "access_control_create",
            "access_control_delete",
            "access_control_search"
        ],
        "name": ["idm_admins_acp_manage"],
        "uuid": ["00000000-0000-0000-0000-ffffff000005"],
        "description": ["Builtin IDM Administrators Access Controls to manage the install."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000001\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Pres\": \"class\"}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": ["name", "class", "uuid", "classname", "attributename", "memberof"],
        "acp_modify_class": ["person"],
        "acp_modify_removedattr": ["class", "displayname", "name", "description"],
        "acp_modify_presentattr": ["class", "displayname", "name", "description"],
        "acp_create_class": ["object", "person", "account"],
        "acp_create_attr": ["name", "class", "description", "displayname"]
    }
}"#;
*/

pub static _UUID_IDM_ALL_ACP_READ_V1: &'static str = "00000000-0000-0000-0000-ffffff000006";
pub static JSON_IDM_ALL_ACP_READ_V1: &'static str = r#"{
    "state": null,
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_all_acp_read"],
        "uuid": ["00000000-0000-0000-0000-ffffff000006"],
        "description": ["Builtin IDM Control for all read - IE anonymous and all authenticated accounts."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Pres\":\"class\"}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Pres\": \"class\"}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name",
            "displayname",
            "class",
            "memberof",
            "member"
        ]
    }
}"#;

// 7 people read acp JSON_IDM_PEOPLE_READ_PRIV_V1
pub static _UUID_IDM_ACP_PEOPLE_READ_PRIV_V1: &'static str = "00000000-0000-0000-0000-ffffff000007";
pub static JSON_IDM_ACP_PEOPLE_READ_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_people_read_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000007"],
        "description": ["Builtin IDM Control for reading personal sensitive data."],
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000008";
pub static JSON_IDM_ACP_PEOPLE_WRITE_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_people_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000008"],
        "description": ["Builtin IDM Control for managing personal and sensitive data."],
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_GROUP_WRITE_PRIV_V1: &'static str = "00000000-0000-0000-0000-ffffff000009";
pub static JSON_IDM_ACP_GROUP_WRITE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000004\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"group\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
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
// 10 account read acp JSON_IDM_ACCOUNT_READ_PRIV_V1
pub static _UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000010";
pub static JSON_IDM_ACP_ACCOUNT_READ_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_account_read_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000010"],
        "description": ["Builtin IDM Control for accounts."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000005\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "uuid", "displayname", "ssh_publickey", "primary_credential", "memberof", "mail"
        ]
    }
}"#;
// 11 account write acp JSON_IDM_ACCOUNT_WRITE_PRIV_V1
pub static _UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000011";
pub static JSON_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000011"],
        "description": ["Builtin IDM Control for managing accounts."],
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000012";
pub static JSON_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000013";
pub static JSON_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_RADIUS_SERVERS_V1: &'static str = "00000000-0000-0000-0000-ffffff000014";
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.
pub static JSON_IDM_ACP_RADIUS_SERVERS_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_radius_servers"],
        "uuid": ["00000000-0000-0000-0000-ffffff000014"],
        "description": ["Builtin IDM Control for RADIUS servers to read credentials and other needed details."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000007\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Pres\": \"class\"}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "name", "uuid", "radius_secret"
        ]
    }
}"#;
// 15 high priv account read JSON_IDM_HP_ACCOUNT_READ_PRIV_V1
pub static _UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000015";
pub static JSON_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_search"
        ],
        "name": ["idm_acp_hp_account_read_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000015"],
        "description": ["Builtin IDM Control for reading high privilege accounts."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000009\"]}"
        ],
        "acp_targetscope": [
            "{\"And\": [{\"Eq\": [\"class\",\"account\"]}, {\"Eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"AndNot\": {\"Or\": [{\"Eq\": [\"class\", \"tombstone\"]}, {\"Eq\": [\"class\", \"recycled\"]}]}}]}"
        ],
        "acp_search_attr": [
            "class", "name", "uuid", "displayname", "ssh_publickey", "primary_credential", "memberof"
        ]
    }
}"#;
// 16 high priv account write JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1
pub static _UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000016";
pub static JSON_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: &'static str = r#"{
    "attrs": {
        "class": [
            "object",
            "access_control_profile",
            "access_control_modify"
        ],
        "name": ["idm_acp_hp_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-ffffff000016"],
        "description": ["Builtin IDM Control for managing high privilege accounts."],
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000017";
pub static JSON_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000018";
pub static JSON_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_ACP_MANAGE_PRIV_V1: &'static str = "00000000-0000-0000-0000-ffffff000019";
pub static JSON_IDM_ACP_ACP_MANAGE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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

pub static _UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000020";
pub static JSON_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000022";
pub static JSON_IDM_ACP_GROUP_MANAGE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000023";
pub static JSON_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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
pub static _UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: &'static str =
    "00000000-0000-0000-0000-ffffff000024";
pub static JSON_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: &'static str = r#"{
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
        "acp_enable": ["true"],
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

// Anonymous should be the last opbject in the range here.
pub static JSON_ANONYMOUS_V1: &'static str = r#"{
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
pub static UUID_SCHEMA_ATTR_CLASS: &'static str = "00000000-0000-0000-0000-ffff00000000";
pub static UUID_SCHEMA_ATTR_UUID: &'static str = "00000000-0000-0000-0000-ffff00000001";
pub static UUID_SCHEMA_ATTR_NAME: &'static str = "00000000-0000-0000-0000-ffff00000002";
pub static UUID_SCHEMA_ATTR_ATTRIBUTENAME: &'static str = "00000000-0000-0000-0000-ffff00000048";
pub static UUID_SCHEMA_ATTR_CLASSNAME: &'static str = "00000000-0000-0000-0000-ffff00000049";
pub static UUID_SCHEMA_ATTR_PRINCIPAL_NAME: &'static str = "00000000-0000-0000-0000-ffff00000003";
pub static UUID_SCHEMA_ATTR_DESCRIPTION: &'static str = "00000000-0000-0000-0000-ffff00000004";
pub static UUID_SCHEMA_ATTR_MULTIVALUE: &'static str = "00000000-0000-0000-0000-ffff00000005";
pub static UUID_SCHEMA_ATTR_UNIQUE: &'static str = "00000000-0000-0000-0000-ffff00000047";
pub static UUID_SCHEMA_ATTR_INDEX: &'static str = "00000000-0000-0000-0000-ffff00000006";
pub static UUID_SCHEMA_ATTR_SYNTAX: &'static str = "00000000-0000-0000-0000-ffff00000007";
pub static UUID_SCHEMA_ATTR_SYSTEMMAY: &'static str = "00000000-0000-0000-0000-ffff00000008";
pub static UUID_SCHEMA_ATTR_MAY: &'static str = "00000000-0000-0000-0000-ffff00000009";
pub static UUID_SCHEMA_ATTR_SYSTEMMUST: &'static str = "00000000-0000-0000-0000-ffff00000010";
pub static UUID_SCHEMA_ATTR_MUST: &'static str = "00000000-0000-0000-0000-ffff00000011";
pub static UUID_SCHEMA_ATTR_MEMBEROF: &'static str = "00000000-0000-0000-0000-ffff00000012";
pub static UUID_SCHEMA_ATTR_MEMBER: &'static str = "00000000-0000-0000-0000-ffff00000013";
pub static UUID_SCHEMA_ATTR_DIRECTMEMBEROF: &'static str = "00000000-0000-0000-0000-ffff00000014";
pub static UUID_SCHEMA_ATTR_VERSION: &'static str = "00000000-0000-0000-0000-ffff00000015";
pub static UUID_SCHEMA_ATTR_DOMAIN: &'static str = "00000000-0000-0000-0000-ffff00000016";
pub static UUID_SCHEMA_ATTR_ACP_ENABLE: &'static str = "00000000-0000-0000-0000-ffff00000017";
pub static UUID_SCHEMA_ATTR_ACP_RECEIVER: &'static str = "00000000-0000-0000-0000-ffff00000018";
pub static UUID_SCHEMA_ATTR_ACP_TARGETSCOPE: &'static str = "00000000-0000-0000-0000-ffff00000019";
pub static UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR: &'static str = "00000000-0000-0000-0000-ffff00000020";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_CLASS: &'static str = "00000000-0000-0000-0000-ffff00000021";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_ATTR: &'static str = "00000000-0000-0000-0000-ffff00000022";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR: &'static str =
    "00000000-0000-0000-0000-ffff00000023";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR: &'static str =
    "00000000-0000-0000-0000-ffff00000024";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS: &'static str = "00000000-0000-0000-0000-ffff00000025";

pub static UUID_SCHEMA_CLASS_ATTRIBUTETYPE: &'static str = "00000000-0000-0000-0000-ffff00000026";
pub static UUID_SCHEMA_CLASS_CLASSTYPE: &'static str = "00000000-0000-0000-0000-ffff00000027";
pub static UUID_SCHEMA_CLASS_OBJECT: &'static str = "00000000-0000-0000-0000-ffff00000028";
pub static UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT: &'static str =
    "00000000-0000-0000-0000-ffff00000029";
pub static UUID_SCHEMA_CLASS_MEMBEROF: &'static str = "00000000-0000-0000-0000-ffff00000030";

pub static UUID_SCHEMA_CLASS_RECYCLED: &'static str = "00000000-0000-0000-0000-ffff00000031";
pub static UUID_SCHEMA_CLASS_TOMBSTONE: &'static str = "00000000-0000-0000-0000-ffff00000032";
pub static UUID_SCHEMA_CLASS_SYSTEM_INFO: &'static str = "00000000-0000-0000-0000-ffff00000033";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE: &'static str =
    "00000000-0000-0000-0000-ffff00000034";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH: &'static str =
    "00000000-0000-0000-0000-ffff00000035";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE: &'static str =
    "00000000-0000-0000-0000-ffff00000036";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY: &'static str =
    "00000000-0000-0000-0000-ffff00000037";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE: &'static str =
    "00000000-0000-0000-0000-ffff00000038";
pub static UUID_SCHEMA_CLASS_SYSTEM: &'static str = "00000000-0000-0000-0000-ffff00000039";

// system supplementary
pub static UUID_SCHEMA_ATTR_DISPLAYNAME: &'static str = "00000000-0000-0000-0000-ffff00000040";
pub static JSON_SCHEMA_ATTR_DISPLAYNAME: &'static str = r#"{
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
pub static UUID_SCHEMA_ATTR_MAIL: &'static str = "00000000-0000-0000-0000-ffff00000041";
pub static JSON_SCHEMA_ATTR_MAIL: &'static str = r#"
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
pub static UUID_SCHEMA_ATTR_SSH_PUBLICKEY: &'static str = "00000000-0000-0000-0000-ffff00000042";
pub static JSON_SCHEMA_ATTR_SSH_PUBLICKEY: &'static str = r#"
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
pub static UUID_SCHEMA_ATTR_PRIMARY_CREDENTIAL: &'static str =
    "00000000-0000-0000-0000-ffff00000043";
pub static JSON_SCHEMA_ATTR_PRIMARY_CREDENTIAL: &'static str = r#"
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
pub static UUID_SCHEMA_ATTR_LEGALNAME: &'static str = "00000000-0000-0000-0000-ffff00000050";
pub static JSON_SCHEMA_ATTR_LEGALNAME: &'static str = r#"{
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
pub static UUID_SCHEMA_ATTR_RADIUS_SECRET: &'static str = "00000000-0000-0000-0000-ffff00000051";
pub static JSON_SCHEMA_ATTR_RADIUS_SECRET: &'static str = r#"{
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

pub static UUID_SCHEMA_CLASS_PERSON: &'static str = "00000000-0000-0000-0000-ffff00000044";
pub static JSON_SCHEMA_CLASS_PERSON: &'static str = r#"
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

pub static UUID_SCHEMA_CLASS_GROUP: &'static str = "00000000-0000-0000-0000-ffff00000045";
pub static JSON_SCHEMA_CLASS_GROUP: &'static str = r#"
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
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000045"
      ]
    }
  }
"#;
pub static UUID_SCHEMA_CLASS_ACCOUNT: &'static str = "00000000-0000-0000-0000-ffff00000046";
pub static JSON_SCHEMA_CLASS_ACCOUNT: &'static str = r#"
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
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000046"
      ]
    }
  }
"#;

// ============ TEST DATA ============
#[cfg(test)]
pub static JSON_TESTPERSON1: &'static str = r#"{
    "valid": null,
    "state": null,
    "attrs": {
        "class": ["object"],
        "name": ["testperson1"],
        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
    }
}"#;

#[cfg(test)]
pub static JSON_TESTPERSON2: &'static str = r#"{
    "valid": null,
    "state": null,
    "attrs": {
        "class": ["object"],
        "name": ["testperson2"],
        "uuid": ["538faac7-4d29-473b-a59d-23023ac19955"]
    }
}"#;
