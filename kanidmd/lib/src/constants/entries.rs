use crate::constants::uuids::*;
///! Constant Entries for the IDM
use crate::constants::values::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::value::Value;
use kanidm_proto::v1::UiHint;

#[cfg(test)]
use uuid::{uuid, Uuid};

/// Builtin System Admin account.
pub const JSON_ADMIN_V1: &str = r#"{
    "attrs": {
        "class": ["account", "service_account", "memberof", "object"],
        "name": ["admin"],
        "uuid": ["00000000-0000-0000-0000-000000000000"],
        "description": ["Builtin System Admin account."],
        "displayname": ["System Administrator"]
    }
}"#;

lazy_static! {
    pub static ref E_ADMIN_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_MEMBEROF.clone()),
        ("class", CLASS_ACCOUNT.clone()),
        ("class", CLASS_SERVICE_ACCOUNT.clone()),
        ("name", Value::new_iname("admin")),
        ("uuid", Value::Uuid(UUID_ADMIN)),
        (
            "description",
            Value::new_utf8s("Builtin System Admin account.")
        ),
        ("displayname", Value::new_utf8s("System Administrator"))
    );
}

/// Builtin IDM Admin account.
pub const JSON_IDM_ADMIN_V1: &str = r#"{
    "attrs": {
        "class": ["account", "service_account", "memberof", "object"],
        "name": ["idm_admin"],
        "uuid": ["00000000-0000-0000-0000-000000000018"],
        "description": ["Builtin IDM Admin account."],
        "displayname": ["IDM Administrator"]
    }
}"#;

/// Builtin IDM Administrators Group.
pub const JSON_IDM_ADMINS_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_admins"],
        "uuid": ["00000000-0000-0000-0000-000000000001"],
        "description": ["Builtin IDM Administrators Group."],
        "member": ["00000000-0000-0000-0000-000000000018"]
    }
}"#;

/// Builtin System Administrators Group.
pub const JSON_SYSTEM_ADMINS_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["system_admins"],
        "uuid": ["00000000-0000-0000-0000-000000000019"],
        "description": ["Builtin System Administrators Group."],
        "member": ["00000000-0000-0000-0000-000000000000"]
    }
}"#;

// * People read managers
/// Builtin IDM Group for granting elevated people (personal data) read permissions.
pub const JSON_IDM_PEOPLE_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000002"],
        "description": ["Builtin IDM Group for granting elevated people (personal data) read permissions."],
        "member": ["00000000-0000-0000-0000-000000000003"]
    }
}"#;

// * People write managers
/// Builtin IDM Group for granting elevated people (personal data) write and lifecycle management permissions.
pub const JSON_IDM_PEOPLE_MANAGE_PRIV_V1: &str = r#"{
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

/// Builtin IDM Group for granting elevated people (personal data) write permissions.
pub const JSON_IDM_PEOPLE_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000003"],
        "description": ["Builtin IDM Group for granting elevated people (personal data) write permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000013",
            "00000000-0000-0000-0000-000000000024"
        ]
    }
}"#;

/// Builtin IDM Group for importing passwords to person accounts - intended for service account membership only.
pub const JSON_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_account_password_import_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000023"],
        "description": ["Builtin IDM Group for importing passwords to person accounts - intended for service account membership only."]
    }
}"#;

/// Builtin IDM Group for allowing the ability to extend accounts to have the "person" flag set.
pub const JSON_IDM_PEOPLE_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000024"],
        "description": ["Builtin IDM Group for extending accounts to be people."],
        "member": [
            "00000000-0000-0000-0000-000000000001"
        ]
    }
}"#;

// Self-write of mail
pub const JSON_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_people_self_write_mail_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000033"],
        "description": ["Builtin IDM Group for people accounts to update their own mail."]
    }
}"#;

/// Builtin IDM Group for granting elevated high privilege people (personal data) read permissions.
pub const JSON_IDM_HP_PEOPLE_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_people_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000028"],
        "description": ["Builtin IDM Group for granting elevated high privilege people (personal data) read permissions."],
        "member": ["00000000-0000-0000-0000-000000000029"]
    }
}"#;

/// Builtin IDM Group for granting elevated high privilege people (personal data) write permissions.
pub const JSON_IDM_HP_PEOPLE_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_people_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000029"],
        "description": ["Builtin IDM Group for granting elevated high privilege people (personal data) write permissions."],
        "member": [
            "00000000-0000-0000-0000-000000000030"
        ]
    }
}"#;

/// Builtin IDM Group for extending high privilege accounts to be people.
pub const JSON_IDM_HP_PEOPLE_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_people_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000030"],
        "description": ["Builtin IDM Group for extending high privilege accounts to be people."],
        "member": [
            "00000000-0000-0000-0000-000000000000"
        ]
    }
}"#;

// * group write manager (no read, everyone has read via the anon, etc)
// IDM_GROUP_CREATE_PRIV
/// Builtin IDM Group for granting elevated group write and lifecycle permissions.
pub const JSON_IDM_GROUP_MANAGE_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_GROUP_WRITE_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_GROUP_UNIX_EXTEND_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_ACCOUNT_READ_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_ACCOUNT_MANAGE_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_ACCOUNT_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000006"],
        "description": ["Builtin IDM Group for granting elevated account write permissions."],
        "member": ["00000000-0000-0000-0000-000000000014"]
    }
}"#;
pub const JSON_IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_account_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000021"],
        "description": ["Builtin IDM Group for granting account unix extend permissions."],
        "member": ["00000000-0000-0000-0000-000000000001"]
    }
}"#;
// * RADIUS servers

/// Builtin IDM Group for RADIUS secret write for all non-hp accounts.
pub const JSON_IDM_RADIUS_SECRET_WRITE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_radius_secret_write_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000031"],
        "description": ["Builtin IDM Group for RADIUS secret write for all non-hp accounts."],
        "member": ["00000000-0000-0000-0000-000000000001"]
    }
}"#;

/// Builtin IDM Group for RADIUS secret reading for all non-hp accounts.
pub const JSON_IDM_RADIUS_SECRET_READ_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_radius_secret_read_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000032"],
        "description": ["Builtin IDM Group for RADIUS secret reading for all non-hp accounts."],
        "member": ["00000000-0000-0000-0000-000000000031"]
    }
}"#;

/// Builtin IDM Group for RADIUS server access delegation.
pub const JSON_IDM_RADIUS_SERVERS_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_radius_servers"],
        "uuid": ["00000000-0000-0000-0000-000000000007"],
        "description": ["Builtin IDM Group for RADIUS server access delegation."]
    }
}"#;

// * high priv account read manager
pub const JSON_IDM_HP_ACCOUNT_READ_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_HP_ACCOUNT_MANAGE_PRIV_V1: &str = r#"{
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

/// Builtin IDM Group for granting elevated account write permissions over high privilege accounts.
pub const JSON_IDM_HP_ACCOUNT_WRITE_PRIV_V1: &str = r#"{
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

/// Builtin IDM Group for granting account unix extend permissions for high privilege accounts.
pub const JSON_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_account_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000025"],
        "description": ["Builtin IDM Group for granting account unix extend permissions for high privilege accounts."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;

// * Schema write manager
pub const JSON_IDM_SCHEMA_MANAGE_PRIV_V1: &str = r#"{
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
pub const JSON_IDM_ACP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_acp_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000011"],
        "description": ["Builtin IDM Group for granting control over all access control profile modifications."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;

// Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups.
pub const JSON_IDM_HP_GROUP_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_group_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000017"],
        "description": ["Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups."],
        "member": ["00000000-0000-0000-0000-000000000019"]
    }
}"#;

/// Builtin IDM Group for granting elevated group write privileges for high privilege groups.
pub const JSON_IDM_HP_GROUP_WRITE_PRIV_V1: &str = r#"{
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

/// Builtin IDM Group for granting unix group extension permissions for high privilege groups.
pub const JSON_IDM_HP_GROUP_UNIX_EXTEND_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_group_unix_extend_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000026"],
        "description": ["Builtin IDM Group for granting unix group extension permissions for high privilege groups."],
        "member": [
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;

/// Builtin IDM Group for granting local domain administration rights and trust administration rights
pub const JSON_DOMAIN_ADMINS: &str = r#"{
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

pub const JSON_IDM_HP_OAUTH2_MANAGE_PRIV_V1: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_oauth2_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000027"],
        "description": ["Builtin IDM Group for managing oauth2 resource server integrations to this authentication domain."],
        "member": [
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;

pub const JSON_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_service_account_into_person_migrate_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000034"],
        "description": ["Builtin IDM Group for allowing migrations of service accounts into persons"],
        "member": [
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;

/// Builtin System Admin account.
pub const JSON_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV: &str = r#"{
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_hp_sync_account_manage_priv"],
        "uuid": ["00000000-0000-0000-0000-000000000037"],
        "description": ["Builtin IDM Group for managing sychronisation from external identity sources"],
        "member": [
            "00000000-0000-0000-0000-000000000019"
        ]
    }
}"#;

// == dyn groups

pub const JSON_IDM_ALL_PERSONS: &str = r#"{
    "attrs": {
        "class": ["dyngroup", "group", "object"],
        "name": ["idm_all_persons"],
        "uuid": ["00000000-0000-0000-0000-000000000035"],
        "description": ["Builtin IDM dynamic group containing all persons that can authenticate"],
        "dyngroup_filter": [
            "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}]}"
        ]
    }
}"#;

pub const JSON_IDM_ALL_ACCOUNTS: &str = r#"{
    "attrs": {
        "class": ["dyngroup", "group", "object"],
        "name": ["idm_all_accounts"],
        "uuid": ["00000000-0000-0000-0000-000000000036"],
        "description": ["Builtin IDM dynamic group containing all entries that can authenticate."],
        "dyngroup_filter": [
            "{\"eq\":[\"class\",\"account\"]}"
        ]
    }
}"#;

lazy_static! {
    pub static ref E_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_GROUP.clone()),
        (
            "name",
            Value::new_iname("idm_ui_enable_experimental_features")
        ),
        (
            "uuid",
            Value::Uuid(UUID_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES)
        ),
        (
            "description",
            Value::new_utf8s(
                "Members of this group will have access to experimental web UI features."
            )
        ),
        ("grant_ui_hint", Value::UiHint(UiHint::ExperimentalFeatures))
    );

    pub static ref E_IDM_ACCOUNT_MAIL_READ_PRIV: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_GROUP.clone()),
        (
            "name",
            Value::new_iname("idm_account_mail_read_priv")
        ),
        (
            "uuid",
            Value::Uuid(UUID_IDM_ACCOUNT_MAIL_READ_PRIV)
        ),
        (
            "description",
            Value::new_utf8s(
                "Members of this group will have access to read the mail attribute of all persons and service accounts."
            )
        )
    );
}

/// This must be the last group to init to include the UUID of the other high priv groups.
pub const JSON_IDM_HIGH_PRIVILEGE_V1: &str = r#"{
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
            "00000000-0000-0000-0000-000000000023",
            "00000000-0000-0000-0000-000000000024",
            "00000000-0000-0000-0000-000000000025",
            "00000000-0000-0000-0000-000000000026",
            "00000000-0000-0000-0000-000000000027",
            "00000000-0000-0000-0000-000000000031",
            "00000000-0000-0000-0000-000000000032",
            "00000000-0000-0000-0000-000000000034",
            "00000000-0000-0000-0000-000000000037",
            "00000000-0000-0000-0000-000000001000"
        ]
    }
}"#;

pub const JSON_SYSTEM_INFO_V1: &str = r#"{
    "attrs": {
        "class": ["object", "system_info", "system"],
        "uuid": ["00000000-0000-0000-0000-ffffff000001"],
        "description": ["System (local) info and metadata object."],
        "version": ["9"]
    }
}"#;

pub const JSON_DOMAIN_INFO_V1: &str = r#"{
    "attrs": {
        "class": ["object", "domain_info", "system"],
        "name": ["domain_local"],
        "uuid": ["00000000-0000-0000-0000-ffffff000025"],
        "description": ["This local domain's info and metadata object."],
        "version": ["1"]
    }
}"#;

// Anonymous should be the last object in the range here.
pub const JSON_ANONYMOUS_V1: &str = r#"{
    "attrs": {
        "class": ["account", "service_account", "object"],
        "name": ["anonymous"],
        "uuid": ["00000000-0000-0000-0000-ffffffffffff"],
        "description": ["Anonymous access account."],
        "displayname": ["Anonymous"]
    }
}"#;

lazy_static! {
    pub static ref E_ANONYMOUS_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCOUNT.clone()),
        ("class", CLASS_SERVICE_ACCOUNT.clone()),
        ("name", Value::new_iname("anonymous")),
        ("uuid", Value::Uuid(UUID_ANONYMOUS)),
        ("description", Value::new_utf8s("Anonymous access account.")),
        ("displayname", Value::new_utf8s("Anonymous"))
    );
}

// ============ TEST DATA ============
#[cfg(test)]
pub const UUID_TESTPERSON_1: Uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

#[cfg(test)]
pub const JSON_TESTPERSON1: &str = r#"{
    "attrs": {
        "class": ["object"],
        "name": ["testperson1"],
        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
    }
}"#;

#[cfg(test)]
pub const UUID_TESTPERSON_2: Uuid = uuid!("538faac7-4d29-473b-a59d-23023ac19955");

#[cfg(test)]
pub const JSON_TESTPERSON2: &str = r#"{
    "attrs": {
        "class": ["object"],
        "name": ["testperson2"],
        "uuid": ["538faac7-4d29-473b-a59d-23023ac19955"]
    }
}"#;

#[cfg(test)]
lazy_static! {
    pub static ref E_TESTPERSON_1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("name", Value::new_iname("testperson1")),
        ("uuid", Value::Uuid(UUID_TESTPERSON_1))
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("name", Value::new_iname("testperson2")),
        ("uuid", Value::Uuid(UUID_TESTPERSON_2))
    );
}
