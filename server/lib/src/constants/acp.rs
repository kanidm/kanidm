#![allow(clippy::expect_used)]
//! Constant Entries for the IDM

use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::prelude::*;
use crate::value::Value;

#[derive(Clone)]
pub struct SchemaAcp {
    classes: Vec<ValueClass>,
    name: &'static str,
    uuid: Uuid,
    description: &'static str,
    receiver_group: Uuid,
    target_scope: TargetScope,
    search_attrs: Vec<ValueAttribute>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetScope {
    And(Vec<TargetScope>),
    Or(Vec<TargetScope>),
    Eq(Vec<TargetScope>),
    #[serde(untagged)]
    Element(&'static str),
}

#[test]
fn test_target_scope() {
    let ts = TargetScope::And(vec![
        TargetScope::Element(ATTR_NAME),
        TargetScope::Element(ATTR_MAIL),
    ]);
    let foo = serde_json::to_string(&ts).unwrap();
    println!("{}", foo);
    assert_eq!(r#"{"and":["name","mail"]}"#, foo);

    let ts = TargetScope::Element(ATTR_SELF);
    let foo = serde_json::to_string(&ts).unwrap();
    println!("{}", foo);
}

impl From<SchemaAcp> for EntryInitNew {
    fn from(value: SchemaAcp) -> Self {
        let mut entry = EntryInitNew::default();

        value.classes.into_iter().for_each(|class| {
            entry.add_ava(ATTR_CLASS, class.to_value());
        });

        entry.set_ava(ATTR_NAME, [Value::new_iname(value.name)]);
        entry.set_ava(ATTR_UUID, [Value::Uuid(value.uuid)]);
        entry.set_ava(ATTR_DESCRIPTION, [Value::new_utf8s(value.description)]);
        entry.set_ava(
            ATTR_ACP_RECEIVER_GROUP,
            [Value::Refer(value.receiver_group)],
        );
        let target_scope = serde_json::to_string(&value.target_scope)
            .unwrap_or_else(|_| panic!("Invalid target scope in definition of {:?}", value.name));

        entry.set_ava(
            ATTR_ACP_TARGET_SCOPE,
            [
                Value::new_json_filter_s(target_scope.as_str()).unwrap_or_else(|| {
                    panic!("Invalid target scope in definition of {:?}", value.name)
                }),
            ],
        );

        entry.set_ava(
            ATTR_ACP_SEARCH_ATTR,
            value
                .search_attrs
                .into_iter()
                .map(|sa| sa.to_value())
                .collect::<Vec<Value>>(),
        );
        entry
    }
}

lazy_static! {
    pub static ref IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: SchemaAcp = SchemaAcp {
        uuid: UUID_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1,
        name: "idm_admins_acp_recycle_search",
        description: "Builtin IDM admin recycle bin search permission.",
        classes: vec![
            ValueClass::Object,
            ValueClass::AccessControlProfile,
            ValueClass::AccessControlSearch,
        ],
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: TargetScope::Eq(vec![
            TargetScope::Element(ATTR_CLASS),
            TargetScope::Element(ATTR_RECYCLED)
        ]),
        search_attrs: vec![
            ValueAttribute::Class,
            ValueAttribute::Name,
            ValueAttribute::Uuid,
            ValueAttribute::LastModifiedCid,
        ],
    };
}
use kanidm_proto::v1::Filter as ProtoFilter;
lazy_static! {
    pub static ref E_IDM_ADMINS_ACP_REVIVE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_admins_acp_revive")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ADMINS_ACP_REVIVE_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM admin recycle bin revive permission.")
        ),
        (ATTR_ACP_RECEIVER_GROUP, Value::Refer(UUID_SYSTEM_ADMINS)),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::JsonFilt(
                ProtoFilter::Eq(ATTR_CLASS.to_string(), ATTR_RECYCLED.to_string())
            )
            // Value::new_json_filter_s("{\"eq\":[\"class\",\"recycled\"]}")
                // .expect("Invalid JSON filter")
        ),
        (
            ATTR_ACP_MODIFY_REMOVEDATTR,
            ValueAttribute::Class.to_value()
        ),
        (ATTR_ACP_MODIFY_CLASS, Value::new_iutf8("recycled"))
    );
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_READ_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_self_acp_read")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_SELF_ACP_READ_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s(
                "Builtin IDM Control for self read - required for whoami and many other functions"
            )
        ),
        (ATTR_ACP_RECEIVER_GROUP, Value::Refer(UUID_IDM_ALL_ACCOUNTS)),
        (
            ATTR_ACP_TARGET_SCOPE,
            // Value::new_json_filter_s("\"self\"").expect("Invalid JSON filter")
            Value::JsonFilt(ProtoFilter::SelfUuid)
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::RadiusSecret.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SyncParentUuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::PrimaryCredential.to_value()),
        (
            ATTR_ACP_SEARCH_ATTR,
            ValueAttribute::UserAuthTokenSession.to_value()
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DeviceKeys.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_self_acp_write")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_SELF_ACP_WRITE_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ALL_PERSONS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::RadiusSecret.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::UserAuthTokenSession.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::RadiusSecret.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DeviceKeys.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACCOUNT_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_self_account_acp_write")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACCOUNT_SELF_ACP_WRITE_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for self write - required for accounts to update their own session state.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_people_self_acp_write_mail")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for self write of mail for people accounts.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ALL_ACP_READ_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_all_acp_read")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ALL_ACP_READ_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for all read - e.g. anonymous and all authenticated accounts.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"or\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"class\",\"group\"]}]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_NAME)),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("spn")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("displayname")),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("memberof")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("member")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_UUID)),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("gidnumber")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("loginshell")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("ssh_publickey"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_READ_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for reading personal sensitive data.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_READ_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing personal and sensitive data.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Mail.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for creating person (user) accounts")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"class\",\"person\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Account.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Person.to_value())
    );
}

// 31 - password import modification priv
// right now, create requires you to have access to every attribute in a single snapshot,
// so people will need to two step (create then import pw). Later we could add another
// acp that allows the create here too? Should it be separate?
lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_account_password_import_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for allowing imports of passwords to people+account types.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::PasswordImport.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PasswordImport.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for allowing person class extension")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_EXTEND_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::Person.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_people_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_READ_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s(
                "Builtin IDM Control for reading high privilege personal sensitive data."
            )
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_PEOPLE_READ_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [
                    {\"eq\": [\"class\",\"person\"]},
                    {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\":
                        {\"or\": [
                            {\"eq\": [\"class\", \"tombstone\"]},
                            {\"eq\": [\"class\", \"recycled\"]}
                        ]}
                    }
                ]}"
            )
            .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (
            ATTR_NAME,
            Value::new_iname("idm_acp_account_mail_read_priv")
        ),
        (
            ATTR_UUID,
            Value::Uuid(UUID_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1)
        ),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s(
                "Builtin IDM Control for reading account mail attributes."
            )
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ACCOUNT_MAIL_READ_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s("{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}")
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_people_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing privilege personal and sensitive data.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_PEOPLE_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_people_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for allowing privilege person class extension")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_PEOPLE_EXTEND_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::Person.to_value())
    );
}

// -- end people

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_group_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_GROUP_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing groups")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_GROUP_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_NAME)),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_UUID)),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("spn")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_UUID)),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("member")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8(ATTR_NAME)),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("member")),
        (ATTR_ACP_MODIFY_PRESENTATTR, Value::new_iutf8(ATTR_NAME)),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Value::new_iutf8("member"))
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for reading accounts.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ACCOUNT_READ_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::ApiTokenSession.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing all accounts (both person and service).")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ACCOUNT_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::ApiTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::UserAuthTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("id_verification_eckey")),

        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::ApiTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for creating and deleting (service) accounts")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ACCOUNT_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Mail.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DeviceKeys.to_value()),

        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Account.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::ServiceAccount.to_value())
    );
}

// 14 radius read acp JSON_IDM_RADIUS_SERVERS_V1
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_radius_secret_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for reading user radius secrets.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_RADIUS_SECRET_READ_PRIV_V1)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::RadiusSecret.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_radius_secret_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control allowing writes to user radius secrets.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::RadiusSecret.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::RadiusSecret.to_value())

    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SERVERS_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_radius_servers")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_RADIUS_SERVERS_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for RADIUS servers to read credentials and other needed details.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_RADIUS_SERVERS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
            "{\"and\": [{\"pres\": \"class\"}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::RadiusSecret.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for reading high privilege accounts.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_ACCOUNT_READ_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::ApiTokenSession.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing high privilege accounts (both person and service).")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_ACCOUNT_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8(ATTR_NAME)),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("displayname")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("ssh_publickey")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("primary_credential")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("account_expire")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("account_valid_from")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("passkeys")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("devicekeys")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("api_token_session")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("user_auth_token_session")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("id_verification_eckey")),

        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::ApiTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_group_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing high privilege groups")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_GROUP_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("dynmember")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Member.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Member.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_schema_write_attrs_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for management of schema attributes.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_SCHEMA_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"attributetype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Index.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Unique.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::MultiValue.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AttributeName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Syntax.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),

        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Index.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Unique.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::MultiValue.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Syntax.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Index.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Unique.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::MultiValue.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Syntax.to_value()),

        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Index.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Unique.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::MultiValue.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AttributeName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Syntax.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Uuid.to_value()),

        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::AttributeType.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_acp_manage_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACP_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for access profiles management.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ACP_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"access_control_profile\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpEnable.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpTargetScope.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpModifyClass.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpCreateClass.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::AcpCreateAttr.to_value()),

        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpEnable.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpTargetScope.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpModifyClass.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpCreateClass.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::AcpCreateAttr.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpEnable.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpTargetScope.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpModifyClass.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpCreateClass.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::AcpCreateAttr.to_value()),

        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpEnable.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpTargetScope.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpModifyClass.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpCreateClass.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AcpCreateAttr.to_value()),


        (ATTR_ACP_MODIFY_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::AccessControlDelete.to_value()),

        (ATTR_ACP_CREATE_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::AccessControlDelete.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_schema_write_classes_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for management of schema classes.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_SCHEMA_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"classtype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::ClassName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SystemMay.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::May.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SystemMust.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Must.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::May.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Must.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::May.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Must.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::ClassName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::May.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Must.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::ClassType.to_value())
    );
}

// 21 - anonymous / everyone schema read.

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_group_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for creating and deleting groups in the directory")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_GROUP_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Member.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Group.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for creating and deleting hp and regular (service) accounts")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_ACCOUNT_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
            "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::PrimaryCredential.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::SshUnderscorePublicKey.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AccountExpire.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::AccountValidFrom.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::PassKeys.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DeviceKeys.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Account.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::ServiceAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_group_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for creating and deleting hp and regular groups in the directory")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_GROUP_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Member.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Group.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_DOMAIN_ADMIN_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_domain_admin_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_DOMAIN_ADMIN_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for granting domain info administration locally")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_DOMAIN_ADMINS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000025\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DomainDisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DomainName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DomainLdapBasedn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DomainSsid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DomainUuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::FernetPrivateKeyStr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::CookiePrivateKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DomainDisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DomainSsid.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DomainLdapBasedn.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::CookiePrivateKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::FernetPrivateKeyStr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DomainDisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DomainLdapBasedn.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DomainSsid.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SYSTEM_CONFIG_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_system_config_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SYSTEM_CONFIG_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for granting system configuration rights")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_SYSTEM_ADMINS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::BadlistPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::BadlistPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::BadlistPassword.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing and extending unix accounts")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::PosixAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_group_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing and extending unix groups")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_GROUP_UNIX_EXTEND_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_NAME)),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8(ATTR_UUID)),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("spn")),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("member")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("gidnumber")),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Value::new_iutf8("gidnumber")),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Value::new_iutf8("gidnumber")),
        (ATTR_ACP_MODIFY_CLASS, Value::new_iutf8("posixgroup"))
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing and extending unix accounts")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::PosixAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_group_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing and extending unix high privilege groups")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DynMember.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::PosixGroup.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_oauth2_manage_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing oauth2 resource server integrations.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_OAUTH2_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"oauth2_resource_server\"]},{\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsBasicSecret.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2RsTokenKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Rs256PrivateKeyDer.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::OAuth2PreferShortUsername.to_value()),

        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsBasicSecret.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2RsTokenKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Rs256PrivateKeyDer.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::OAuth2PreferShortUsername.to_value()),


        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2RsName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::OAuth2PreferShortUsername.to_value()),

        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2RsName.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::OAuth2PreferShortUsername.to_value()),


        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::OAuth2ResourceServer.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::OAuth2ResourceServerBasic.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::OAuth2ResourceServerPublic.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_hp_acp_service_account_into_person_migrate")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control allowing service accounts to be migrated into persons")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::ServiceAccount.to_value()),
        (ATTR_ACP_MODIFY_CLASS, ValueClass::Person.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, ValueClass::Object.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlModify.to_value()),
        (ATTR_CLASS, ValueClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_sync_account_manage_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Control for managing IDM synchronisation accounts / connections")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"sync_account\"]},{\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::JwsEs256PrivateKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SyncTokenSession.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SyncCredentialPortal.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SyncYieldAuthority.to_value()),
        (ATTR_ACP_SEARCH_ATTR, ValueAttribute::SyncCookie.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::JwsEs256PrivateKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::SyncTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::SyncCredentialPortal.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::SyncCookie.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, ValueAttribute::SyncYieldAuthority.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::SyncTokenSession.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::SyncCredentialPortal.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, ValueAttribute::SyncYieldAuthority.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, ValueAttribute::Description.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, ValueClass::SyncAccount.to_value())
    );
}
