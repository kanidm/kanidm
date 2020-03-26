use uuid::Uuid;

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
pub static _UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV: &str =
    "00000000-0000-0000-0000-000000000023";
pub static _UUID_IDM_PEOPLE_EXTEND_PRIV: &str = "00000000-0000-0000-0000-000000000024";
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
pub static UUID_SCHEMA_ATTR_UNIX_PASSWORD: &str = "00000000-0000-0000-0000-ffff00000062";
pub static UUID_SCHEMA_ATTR_LAST_MOD_CID: &str = "00000000-0000-0000-0000-ffff00000063";
pub static UUID_SCHEMA_ATTR_PHANTOM: &str = "00000000-0000-0000-0000-ffff00000064";
pub static UUID_SCHEMA_ATTR_CLAIM: &str = "00000000-0000-0000-0000-ffff00000065";
pub static UUID_SCHEMA_ATTR_PASSWORD_IMPORT: &str = "00000000-0000-0000-0000-ffff00000066";

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
pub static _UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: &str =
    "00000000-0000-0000-0000-ffffff000031";
pub static _UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1: &str = "00000000-0000-0000-0000-ffffff000032";

// End of system ranges
pub static STR_UUID_DOES_NOT_EXIST: &str = "00000000-0000-0000-0000-fffffffffffe";
pub static STR_UUID_ANONYMOUS: &str = "00000000-0000-0000-0000-ffffffffffff";

lazy_static! {
    pub static ref UUID_ADMIN: Uuid = Uuid::parse_str(STR_UUID_ADMIN).unwrap();
    pub static ref UUID_DOES_NOT_EXIST: Uuid = Uuid::parse_str(STR_UUID_DOES_NOT_EXIST).unwrap();
    pub static ref UUID_ANONYMOUS: Uuid = Uuid::parse_str(STR_UUID_ANONYMOUS).unwrap();
    pub static ref UUID_SYSTEM_CONFIG: Uuid = Uuid::parse_str(STR_UUID_SYSTEM_CONFIG).unwrap();
}
