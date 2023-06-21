#![allow(clippy::expect_used)]
//! Constant Entries for the IDM

use crate::constants::uuids::*;
use crate::constants::values::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::value::Value;

lazy_static! {
    pub static ref E_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_admins_acp_recycle_search")),
        ("uuid", Value::Uuid(UUID_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM admin recycle bin search permission.")
        ),
        ("acp_receiver_group", Value::Refer(UUID_SYSTEM_ADMINS)),
        (
            "acp_targetscope",
            Value::new_json_filter_s("{\"eq\": [\"class\", \"recycled\"]}")
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("last_modified_cid"))
    );
}

lazy_static! {
    pub static ref E_IDM_ADMINS_ACP_REVIVE_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_admins_acp_revive")),
        ("uuid", Value::Uuid(UUID_IDM_ADMINS_ACP_REVIVE_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM admin recycle bin revive permission.")
        ),
        ("acp_receiver_group", Value::Refer(UUID_SYSTEM_ADMINS)),
        (
            "acp_targetscope",
            Value::new_json_filter_s("{\"eq\":[\"class\",\"recycled\"]}")
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("class")),
        ("acp_modify_class", Value::new_iutf8("recycled"))
    );
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_READ_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_self_acp_read")),
        ("uuid", Value::Uuid(UUID_IDM_SELF_ACP_READ_V1)),
        (
            "description",
            Value::new_utf8s(
                "Builtin IDM Control for self read - required for whoami and many other functions"
            )
        ),
        ("acp_receiver_group", Value::Refer(UUID_IDM_ALL_ACCOUNTS)),
        (
            "acp_targetscope",
            Value::new_json_filter_s("\"self\"").expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("legalname")),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("memberof")),
        ("acp_search_attr", Value::new_iutf8("mail")),
        ("acp_search_attr", Value::new_iutf8("radius_secret")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_search_attr", Value::new_iutf8("loginshell")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("account_expire")),
        ("acp_search_attr", Value::new_iutf8("account_valid_from")),
        ("acp_search_attr", Value::new_iutf8("primary_credential")),
        (
            "acp_search_attr",
            Value::new_iutf8("user_auth_token_session")
        ),
        ("acp_search_attr", Value::new_iutf8("passkeys")),
        ("acp_search_attr", Value::new_iutf8("devicekeys"))
    );
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_self_acp_write")),
        ("uuid", Value::Uuid(UUID_IDM_SELF_ACP_WRITE_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ALL_PERSONS)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("legalname")),
        ("acp_modify_removedattr", Value::new_iutf8("radius_secret")),
        ("acp_modify_removedattr", Value::new_iutf8("primary_credential")),
        ("acp_modify_removedattr", Value::new_iutf8("ssh_publickey")),
        ("acp_modify_removedattr", Value::new_iutf8("unix_password")),
        ("acp_modify_removedattr", Value::new_iutf8("passkeys")),
        ("acp_modify_removedattr", Value::new_iutf8("devicekeys")),
        ("acp_modify_removedattr", Value::new_iutf8("user_auth_token_session")),

        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("legalname")),
        ("acp_modify_presentattr", Value::new_iutf8("radius_secret")),
        ("acp_modify_presentattr", Value::new_iutf8("primary_credential")),
        ("acp_modify_presentattr", Value::new_iutf8("ssh_publickey")),
        ("acp_modify_presentattr", Value::new_iutf8("unix_password")),
        ("acp_modify_presentattr", Value::new_iutf8("passkeys")),
        ("acp_modify_presentattr", Value::new_iutf8("devicekeys"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACCOUNT_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_self_account_acp_write")),
        ("uuid", Value::Uuid(UUID_IDM_ACCOUNT_SELF_ACP_WRITE_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for self write - required for accounts to update their own session state.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("user_auth_token_session"))
    );
}

lazy_static! {
    pub static ref E_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_people_self_acp_write_mail")),
        ("uuid", Value::Uuid(UUID_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for self write of mail for people accounts.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("mail")),
        ("acp_modify_presentattr", Value::new_iutf8("mail"))
    );
}

lazy_static! {
    pub static ref E_IDM_ALL_ACP_READ_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_all_acp_read")),
        ("uuid", Value::Uuid(UUID_IDM_ALL_ACP_READ_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for all read - e.g. anonymous and all authenticated accounts.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"pres\": \"class\"}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("memberof")),
        ("acp_search_attr", Value::new_iutf8("member")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_search_attr", Value::new_iutf8("loginshell")),
        ("acp_search_attr", Value::new_iutf8("ssh_publickey"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_people_read_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_PEOPLE_READ_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for reading personal sensitive data.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_PEOPLE_READ_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("legalname")),
        ("acp_search_attr", Value::new_iutf8("mail"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_people_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing personal and sensitive data.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_PEOPLE_WRITE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("legalname")),
        ("acp_modify_removedattr", Value::new_iutf8("mail")),

        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("legalname")),
        ("acp_modify_presentattr", Value::new_iutf8("mail"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("name", Value::new_iname("idm_acp_people_manage")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for creating person (user) accounts")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_PEOPLE_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"class\",\"person\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("displayname")),
        ("acp_create_attr", Value::new_iutf8("legalname")),
        ("acp_create_attr", Value::new_iutf8("primary_credential")),
        ("acp_create_attr", Value::new_iutf8("ssh_publickey")),
        ("acp_create_attr", Value::new_iutf8("mail")),
        ("acp_create_attr", Value::new_iutf8("account_expire")),
        ("acp_create_attr", Value::new_iutf8("account_valid_from")),
        ("acp_create_attr", Value::new_iutf8("passkeys")),
        ("acp_create_attr", Value::new_iutf8("devicekeys")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("account")),
        ("acp_create_class", Value::new_iutf8("person"))
    );
}

// 31 - password import modification priv
// right now, create requires you to have access to every attribute in a single snapshot,
// so people will need to two step (create then import pw). Later we could add another
// acp that allows the create here too? Should it be separate?
lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_people_account_password_import_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for allowing imports of passwords to people+account types.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("password_import")),
        ("acp_modify_presentattr", Value::new_iutf8("password_import"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_people_extend_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for allowing person class extension")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_PEOPLE_EXTEND_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("legalname")),
        ("acp_modify_removedattr", Value::new_iutf8("mail")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("legalname")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_class", Value::new_iutf8("person"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_people_read_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_READ_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for reading high privilege personal sensitive data.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_PEOPLE_READ_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("legalname")),
        ("acp_search_attr", Value::new_iutf8("mail"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        (
            "name",
            Value::new_iname("idm_acp_account_mail_read_priv")
        ),
        (
            "uuid",
            Value::Uuid(UUID_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1)
        ),
        (
            "description",
            Value::new_utf8s(
                "Builtin IDM Control for reading account mail attributes."
            )
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ACCOUNT_MAIL_READ_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s("{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}")
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("mail"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_hp_people_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing privilege personal and sensitive data.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_PEOPLE_WRITE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("legalname")),
        ("acp_modify_removedattr", Value::new_iutf8("mail")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("legalname")),
        ("acp_modify_presentattr", Value::new_iutf8("name"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_hp_people_extend_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for allowing privilege person class extension")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_PEOPLE_EXTEND_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("legalname")),
        ("acp_modify_removedattr", Value::new_iutf8("mail")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("legalname")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_class", Value::new_iutf8("person"))
    );
}

// -- end people

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_group_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_GROUP_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing groups")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_GROUP_WRITE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("member")),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("member")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("member"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_account_read_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for reading accounts.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ACCOUNT_READ_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("ssh_publickey")),
        ("acp_search_attr", Value::new_iutf8("primary_credential")),
        ("acp_search_attr", Value::new_iutf8("memberof")),
        ("acp_search_attr", Value::new_iutf8("mail")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_search_attr", Value::new_iutf8("account_expire")),
        ("acp_search_attr", Value::new_iutf8("account_valid_from")),
        ("acp_search_attr", Value::new_iutf8("passkeys")),
        ("acp_search_attr", Value::new_iutf8("devicekeys")),
        ("acp_search_attr", Value::new_iutf8("api_token_session")),
        ("acp_search_attr", Value::new_iutf8("user_auth_token_session"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_account_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing all accounts (both person and service).")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ACCOUNT_WRITE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("ssh_publickey")),
        ("acp_modify_removedattr", Value::new_iutf8("primary_credential")),
        ("acp_modify_removedattr", Value::new_iutf8("mail")),
        ("acp_modify_removedattr", Value::new_iutf8("account_expire")),
        ("acp_modify_removedattr", Value::new_iutf8("account_valid_from")),
        ("acp_modify_removedattr", Value::new_iutf8("passkeys")),
        ("acp_modify_removedattr", Value::new_iutf8("devicekeys")),
        ("acp_modify_removedattr", Value::new_iutf8("api_token_session")),
        ("acp_modify_removedattr", Value::new_iutf8("user_auth_token_session")),

        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("ssh_publickey")),
        ("acp_modify_presentattr", Value::new_iutf8("primary_credential")),
        ("acp_modify_presentattr", Value::new_iutf8("mail")),
        ("acp_modify_presentattr", Value::new_iutf8("account_expire")),
        ("acp_modify_presentattr", Value::new_iutf8("account_valid_from")),
        ("acp_modify_presentattr", Value::new_iutf8("passkeys")),
        ("acp_modify_presentattr", Value::new_iutf8("devicekeys")),
        ("acp_modify_presentattr", Value::new_iutf8("api_token_session"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("name", Value::new_iname("idm_acp_account_manage")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for creating and deleting (service) accounts")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ACCOUNT_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("displayname")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("primary_credential")),
        ("acp_create_attr", Value::new_iutf8("ssh_publickey")),
        ("acp_create_attr", Value::new_iutf8("mail")),
        ("acp_create_attr", Value::new_iutf8("account_expire")),
        ("acp_create_attr", Value::new_iutf8("account_valid_from")),
        ("acp_create_attr", Value::new_iutf8("passkeys")),
        ("acp_create_attr", Value::new_iutf8("devicekeys")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("account")),
        ("acp_create_class", Value::new_iutf8("service_account"))
    );
}

// 14 radius read acp JSON_IDM_RADIUS_SERVERS_V1
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_radius_secret_read_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for reading user radius secrets.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_RADIUS_SECRET_READ_PRIV_V1)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("radius_secret"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_radius_secret_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control allowing writes to user radius secrets.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("radius_secret")),
        ("acp_modify_presentattr", Value::new_iutf8("radius_secret"))

    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SERVERS_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_radius_servers")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_RADIUS_SERVERS_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for RADIUS servers to read credentials and other needed details.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_RADIUS_SERVERS)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
            "{\"and\": [{\"pres\": \"class\"}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("radius_secret"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_account_read_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for reading high privilege accounts.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_ACCOUNT_READ_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("ssh_publickey")),
        ("acp_search_attr", Value::new_iutf8("primary_credential")),
        ("acp_search_attr", Value::new_iutf8("memberof")),
        ("acp_search_attr", Value::new_iutf8("account_expire")),
        ("acp_search_attr", Value::new_iutf8("account_valid_from")),
        ("acp_search_attr", Value::new_iutf8("passkeys")),
        ("acp_search_attr", Value::new_iutf8("devicekeys")),
        ("acp_search_attr", Value::new_iutf8("api_token_session")),
        ("acp_search_attr", Value::new_iutf8("user_auth_token_session"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("name", Value::new_iname("idm_acp_hp_account_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing high privilege accounts (both person and service).")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_ACCOUNT_WRITE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("ssh_publickey")),
        ("acp_modify_removedattr", Value::new_iutf8("primary_credential")),
        ("acp_modify_removedattr", Value::new_iutf8("account_expire")),
        ("acp_modify_removedattr", Value::new_iutf8("account_valid_from")),
        ("acp_modify_removedattr", Value::new_iutf8("passkeys")),
        ("acp_modify_removedattr", Value::new_iutf8("devicekeys")),
        ("acp_modify_removedattr", Value::new_iutf8("api_token_session")),
        ("acp_modify_removedattr", Value::new_iutf8("user_auth_token_session")),

        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("ssh_publickey")),
        ("acp_modify_presentattr", Value::new_iutf8("primary_credential")),
        ("acp_modify_presentattr", Value::new_iutf8("account_expire")),
        ("acp_modify_presentattr", Value::new_iutf8("account_valid_from")),
        ("acp_modify_presentattr", Value::new_iutf8("passkeys")),
        ("acp_modify_presentattr", Value::new_iutf8("devicekeys")),
        ("acp_modify_presentattr", Value::new_iutf8("api_token_session"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_group_write_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing high privilege groups")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_GROUP_WRITE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("member")),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("member")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("member"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_schema_write_attrs_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for management of schema attributes.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_SCHEMA_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"attributetype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("index")),
        ("acp_search_attr", Value::new_iutf8("unique")),
        ("acp_search_attr", Value::new_iutf8("multivalue")),
        ("acp_search_attr", Value::new_iutf8("attributename")),
        ("acp_search_attr", Value::new_iutf8("syntax")),
        ("acp_search_attr", Value::new_iutf8("uuid")),

        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("index")),
        ("acp_modify_removedattr", Value::new_iutf8("unique")),
        ("acp_modify_removedattr", Value::new_iutf8("multivalue")),
        ("acp_modify_removedattr", Value::new_iutf8("syntax")),

        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("index")),
        ("acp_modify_presentattr", Value::new_iutf8("unique")),
        ("acp_modify_presentattr", Value::new_iutf8("multivalue")),
        ("acp_modify_presentattr", Value::new_iutf8("syntax")),

        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("index")),
        ("acp_create_attr", Value::new_iutf8("unique")),
        ("acp_create_attr", Value::new_iutf8("multivalue")),
        ("acp_create_attr", Value::new_iutf8("attributename")),
        ("acp_create_attr", Value::new_iutf8("syntax")),
        ("acp_create_attr", Value::new_iutf8("uuid")),

        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("attributetype"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_acp_manage_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_ACP_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for access profiles management.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ACP_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"access_control_profile\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("acp_enable")),
        ("acp_search_attr", Value::new_iutf8("acp_receiver_group")),
        ("acp_search_attr", Value::new_iutf8("acp_targetscope")),
        ("acp_search_attr", Value::new_iutf8("acp_search_attr")),
        ("acp_search_attr", Value::new_iutf8("acp_modify_removedattr")),
        ("acp_search_attr", Value::new_iutf8("acp_modify_presentattr")),
        ("acp_search_attr", Value::new_iutf8("acp_modify_class")),
        ("acp_search_attr", Value::new_iutf8("acp_create_class")),
        ("acp_search_attr", Value::new_iutf8("acp_create_attr")),

        ("acp_modify_removedattr", Value::new_iutf8("class")),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_enable")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_receiver_group")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_targetscope")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_search_attr")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_modify_removedattr")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_modify_presentattr")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_modify_class")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_create_class")),
        ("acp_modify_removedattr", Value::new_iutf8("acp_create_attr")),

        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_enable")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_receiver_group")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_targetscope")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_search_attr")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_modify_removedattr")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_modify_presentattr")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_modify_class")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_create_class")),
        ("acp_modify_presentattr", Value::new_iutf8("acp_create_attr")),

        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("acp_enable")),
        ("acp_create_attr", Value::new_iutf8("acp_receiver_group")),
        ("acp_create_attr", Value::new_iutf8("acp_targetscope")),
        ("acp_create_attr", Value::new_iutf8("acp_search_attr")),
        ("acp_create_attr", Value::new_iutf8("acp_modify_removedattr")),
        ("acp_create_attr", Value::new_iutf8("acp_modify_presentattr")),
        ("acp_create_attr", Value::new_iutf8("acp_modify_class")),
        ("acp_create_attr", Value::new_iutf8("acp_create_class")),
        ("acp_create_attr", Value::new_iutf8("acp_create_attr")),


        ("acp_modify_class", Value::new_iutf8("access_control_profile")),
        ("acp_modify_class", Value::new_iutf8("access_control_search")),
        ("acp_modify_class", Value::new_iutf8("access_control_modify")),
        ("acp_modify_class", Value::new_iutf8("access_control_create")),
        ("acp_modify_class", Value::new_iutf8("access_control_delete")),

        ("acp_create_class", Value::new_iutf8("access_control_profile")),
        ("acp_create_class", Value::new_iutf8("access_control_search")),
        ("acp_create_class", Value::new_iutf8("access_control_modify")),
        ("acp_create_class", Value::new_iutf8("access_control_create")),
        ("acp_create_class", Value::new_iutf8("access_control_delete"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_schema_write_classes_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for management of schema classes.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_SCHEMA_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"classtype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("classname")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("systemmay")),
        ("acp_search_attr", Value::new_iutf8("may")),
        ("acp_search_attr", Value::new_iutf8("systemmust")),
        ("acp_search_attr", Value::new_iutf8("must")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_modify_removedattr", Value::new_iutf8("class")),
        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("may")),
        ("acp_modify_removedattr", Value::new_iutf8("must")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("may")),
        ("acp_modify_presentattr", Value::new_iutf8("must")),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("classname")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("may")),
        ("acp_create_attr", Value::new_iutf8("must")),
        ("acp_create_attr", Value::new_iutf8("uuid")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("classtype"))
    );
}

// 21 - anonymous / everyone schema read.

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("name", Value::new_iname("idm_acp_group_manage")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for creating and deleting groups in the directory")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_GROUP_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("member")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("group"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("name", Value::new_iname("idm_acp_hp_account_manage")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for creating and deleting hp and regular (service) accounts")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_ACCOUNT_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
            "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("displayname")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("primary_credential")),
        ("acp_create_attr", Value::new_iutf8("ssh_publickey")),
        ("acp_create_attr", Value::new_iutf8("account_expire")),
        ("acp_create_attr", Value::new_iutf8("account_valid_from")),
        ("acp_create_attr", Value::new_iutf8("passkeys")),
        ("acp_create_attr", Value::new_iutf8("devicekeys")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("account")),
        ("acp_create_class", Value::new_iutf8("service_account"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("name", Value::new_iname("idm_acp_hp_group_manage")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for creating and deleting hp and regular groups in the directory")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_GROUP_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("member")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("group"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_DOMAIN_ADMIN_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_domain_admin_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_DOMAIN_ADMIN_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for granting domain info administration locally")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_DOMAIN_ADMINS)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000025\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("domain_display_name")),
        ("acp_search_attr", Value::new_iutf8("domain_name")),
        ("acp_search_attr", Value::new_iutf8("domain_ldap_basedn")),
        ("acp_search_attr", Value::new_iutf8("domain_ssid")),
        ("acp_search_attr", Value::new_iutf8("domain_uuid")),
        ("acp_search_attr", Value::new_iutf8("es256_private_key_der")),
        ("acp_search_attr", Value::new_iutf8("fernet_private_key_str")),
        ("acp_search_attr", Value::new_iutf8("cookie_private_key")),
        ("acp_modify_removedattr", Value::new_iutf8("domain_display_name")),
        ("acp_modify_removedattr", Value::new_iutf8("domain_ssid")),
        ("acp_modify_removedattr", Value::new_iutf8("domain_ldap_basedn")),
        ("acp_modify_removedattr", Value::new_iutf8("es256_private_key_der")),
        ("acp_modify_removedattr", Value::new_iutf8("cookie_private_key")),
        ("acp_modify_removedattr", Value::new_iutf8("fernet_private_key_str")),
        ("acp_modify_presentattr", Value::new_iutf8("domain_display_name")),
        ("acp_modify_presentattr", Value::new_iutf8("domain_ldap_basedn")),
        ("acp_modify_presentattr", Value::new_iutf8("domain_ssid"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SYSTEM_CONFIG_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_system_config_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_SYSTEM_CONFIG_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for granting system configuration rights")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_SYSTEM_ADMINS)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("badlist_password")),
        ("acp_modify_removedattr", Value::new_iutf8("badlist_password")),
        ("acp_modify_presentattr", Value::new_iutf8("badlist_password"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_account_unix_extend_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing and extending unix accounts")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_search_attr", Value::new_iutf8("loginshell")),
        ("acp_search_attr", Value::new_iutf8("unix_password")),
        ("acp_modify_removedattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_removedattr", Value::new_iutf8("loginshell")),
        ("acp_modify_removedattr", Value::new_iutf8("unix_password")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_presentattr", Value::new_iutf8("loginshell")),
        ("acp_modify_presentattr", Value::new_iutf8("unix_password")),
        ("acp_modify_class", Value::new_iutf8("posixaccount"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_group_unix_extend_priv")),
        ("uuid", Value::Uuid(UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing and extending unix groups")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_GROUP_UNIX_EXTEND_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("member")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_modify_removedattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_class", Value::new_iutf8("posixgroup"))
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_account_unix_extend_priv")),
        ("uuid", Value::Uuid(UUID_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing and extending unix accounts")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_search_attr", Value::new_iutf8("loginshell")),
        ("acp_search_attr", Value::new_iutf8("unix_password")),
        ("acp_modify_removedattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_removedattr", Value::new_iutf8("loginshell")),
        ("acp_modify_removedattr", Value::new_iutf8("unix_password")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_presentattr", Value::new_iutf8("loginshell")),
        ("acp_modify_presentattr", Value::new_iutf8("unix_password")),
        ("acp_modify_class", Value::new_iutf8("posixaccount"))
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_group_unix_extend_priv")),
        ("uuid", Value::Uuid(UUID_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing and extending unix high privilege groups")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_search_attr", Value::new_iutf8("spn")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("member")),
        ("acp_search_attr", Value::new_iutf8("gidnumber")),
        ("acp_modify_removedattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("gidnumber")),
        ("acp_modify_class", Value::new_iutf8("posixgroup"))
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_oauth2_manage_priv")),
        ("uuid", Value::Uuid(UUID_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing oauth2 resource server integrations.")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_OAUTH2_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"oauth2_resource_server\"]},{\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("displayname")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_name")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_origin")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_origin_landing")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_scope_map")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_sup_scope_map")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_basic_secret")),
        ("acp_search_attr", Value::new_iutf8("oauth2_rs_token_key")),
        ("acp_search_attr", Value::new_iutf8("es256_private_key_der")),
        ("acp_search_attr", Value::new_iutf8("oauth2_allow_insecure_client_disable_pkce")),
        ("acp_search_attr", Value::new_iutf8("rs256_private_key_der")),
        ("acp_search_attr", Value::new_iutf8("oauth2_jwt_legacy_crypto_enable")),
        ("acp_search_attr", Value::new_iutf8("oauth2_prefer_short_username")),

        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("displayname")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_name")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_origin")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_origin_landing")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_scope_map")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_sup_scope_map")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_basic_secret")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_rs_token_key")),
        ("acp_modify_removedattr", Value::new_iutf8("es256_private_key_der")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_allow_insecure_client_disable_pkce")),
        ("acp_modify_removedattr", Value::new_iutf8("rs256_private_key_der")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_jwt_legacy_crypto_enable")),
        ("acp_modify_removedattr", Value::new_iutf8("oauth2_prefer_short_username")),


        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("displayname")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_rs_name")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_rs_origin")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_rs_origin_landing")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_rs_sup_scope_map")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_rs_scope_map")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_allow_insecure_client_disable_pkce")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_jwt_legacy_crypto_enable")),
        ("acp_modify_presentattr", Value::new_iutf8("oauth2_prefer_short_username")),

        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_attr", Value::new_iutf8("displayname")),
        ("acp_create_attr", Value::new_iutf8("oauth2_rs_name")),
        ("acp_create_attr", Value::new_iutf8("oauth2_rs_origin")),
        ("acp_create_attr", Value::new_iutf8("oauth2_rs_origin_landing")),
        ("acp_create_attr", Value::new_iutf8("oauth2_rs_sup_scope_map")),
        ("acp_create_attr", Value::new_iutf8("oauth2_rs_scope_map")),
        ("acp_create_attr", Value::new_iutf8("oauth2_allow_insecure_client_disable_pkce")),
        ("acp_create_attr", Value::new_iutf8("oauth2_jwt_legacy_crypto_enable")),
        ("acp_create_attr", Value::new_iutf8("oauth2_prefer_short_username")),


        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("oauth2_resource_server")),
        ("acp_create_class", Value::new_iutf8("oauth2_resource_server_basic"))
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_hp_acp_service_account_into_person_migrate")),
        ("uuid", Value::Uuid(UUID_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control allowing service accounts to be migrated into persons")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("uuid")),
        ("acp_modify_removedattr", Value::new_iutf8("class")),
        ("acp_modify_presentattr", Value::new_iutf8("class")),
        ("acp_modify_class", Value::new_iutf8("service_account")),
        ("acp_modify_class", Value::new_iutf8("person"))
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        ("class", CLASS_OBJECT.clone()),
        ("class", CLASS_ACCESS_CONTROL_PROFILE.clone()),
        ("class", CLASS_ACCESS_CONTROL_CREATE.clone()),
        ("class", CLASS_ACCESS_CONTROL_DELETE.clone()),
        ("class", CLASS_ACCESS_CONTROL_MODIFY.clone()),
        ("class", CLASS_ACCESS_CONTROL_SEARCH.clone()),
        ("name", Value::new_iname("idm_acp_hp_sync_account_manage_priv")),
        ("uuid", Value::Uuid(UUID_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1)),
        (
            "description",
            Value::new_utf8s("Builtin IDM Control for managing IDM synchronisation accounts / connections")
        ),
        (
            "acp_receiver_group",
            Value::Refer(UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV)
        ),
        (
            "acp_targetscope",
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"sync_account\"]},{\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        ("acp_search_attr", Value::new_iutf8("class")),
        ("acp_search_attr", Value::new_iutf8("name")),
        ("acp_search_attr", Value::new_iutf8("description")),
        ("acp_search_attr", Value::new_iutf8("jws_es256_private_key")),
        ("acp_search_attr", Value::new_iutf8("sync_token_session")),
        ("acp_search_attr", Value::new_iutf8("sync_cookie")),
        ("acp_modify_removedattr", Value::new_iutf8("name")),
        ("acp_modify_removedattr", Value::new_iutf8("description")),
        ("acp_modify_removedattr", Value::new_iutf8("jws_es256_private_key")),
        ("acp_modify_removedattr", Value::new_iutf8("sync_token_session")),
        ("acp_modify_removedattr", Value::new_iutf8("sync_cookie")),
        ("acp_modify_presentattr", Value::new_iutf8("name")),
        ("acp_modify_presentattr", Value::new_iutf8("description")),
        ("acp_modify_presentattr", Value::new_iutf8("sync_token_session")),
        ("acp_create_attr", Value::new_iutf8("class")),
        ("acp_create_attr", Value::new_iutf8("name")),
        ("acp_create_attr", Value::new_iutf8("description")),
        ("acp_create_class", Value::new_iutf8("object")),
        ("acp_create_class", Value::new_iutf8("sync_account"))
    );
}
