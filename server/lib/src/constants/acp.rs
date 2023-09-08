#![allow(clippy::expect_used)]
//! Constant Entries for the IDM

use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::prelude::*;
use crate::value::Value;
use kanidm_proto::v1::Filter as ProtoFilter;

#[derive(Clone)]
/// Built-in Access Control Profile definitions
pub struct BuiltinAcp {
    classes: Vec<EntryClass>,
    name: &'static str,
    uuid: Uuid,
    description: &'static str,
    receiver_group: Uuid,
    target_scope: ProtoFilter,
    search_attrs: Vec<Attribute>,
    modify_removed_attrs: Vec<Attribute>,
    modify_classes: Vec<EntryClass>,
}

impl Default for BuiltinAcp {
    fn default() -> Self {
        Self {
            classes: Default::default(),
            name: Default::default(),
            uuid: Default::default(),
            description: Default::default(),
            receiver_group: Default::default(),
            search_attrs: Default::default(),
            modify_removed_attrs: Default::default(),
            modify_classes: Default::default(),
            target_scope: ProtoFilter::SelfUuid,
        }
    }
}

impl From<BuiltinAcp> for EntryInitNew {
    fn from(value: BuiltinAcp) -> Self {
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
        entry.set_ava(ATTR_ACP_TARGET_SCOPE, [Value::JsonFilt(value.target_scope)]);

        entry.set_ava(
            ATTR_ACP_SEARCH_ATTR,
            value
                .search_attrs
                .into_iter()
                .map(|sa| sa.to_value())
                .collect::<Vec<Value>>(),
        );
        value.modify_removed_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyRemovedAttr.as_ref(), attr.to_value());
        });
        value.modify_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyClass.as_ref(), class.to_value());
        });
        entry
    }
}

lazy_static! {
    pub static ref IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: BuiltinAcp = BuiltinAcp {
        uuid: UUID_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1,
        name: "idm_admins_acp_recycle_search",
        description: "Builtin IDM admin recycle bin search permission.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: ProtoFilter::Eq(ATTR_CLASS.to_string(), ATTR_RECYCLED.to_string()),

        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::LastModifiedCid,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ADMINS_ACP_REVIVE_V1: BuiltinAcp = BuiltinAcp {
        uuid: UUID_IDM_ADMINS_ACP_REVIVE_V1,
        name: "idm_admins_acp_revive",
        description: "Builtin IDM admin recycle bin revive permission.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: ProtoFilter::Eq(ATTR_CLASS.to_string(), ATTR_RECYCLED.to_string()),
        modify_removed_attrs: vec![Attribute::Class],
        search_attrs: vec![],
        modify_classes: vec![EntryClass::Recycled],
    };
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_READ_V1: EntryInitNew =
        entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_self_acp_read")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_SELF_ACP_READ_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s(
                "Builtin IDM Control for self read - required for whoami and many other functions"
            )
        ),
        (ATTR_ACP_RECEIVER_GROUP, Value::Refer(UUID_IDM_ALL_ACCOUNTS)),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::JsonFilt(ProtoFilter::SelfUuid)
        ),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::RadiusSecret.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SyncParentUuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PrimaryCredential.to_value()),
        (
            ATTR_ACP_SEARCH_ATTR,
            Attribute::UserAuthTokenSession.to_value()
        ),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DeviceKeys.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_self_acp_write")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_SELF_ACP_WRITE_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ALL_PERSONS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            // Value::JsonFilt(ProtoFilter::And(vec![
            //     ProtoFilter::Eq(Attribute::Class.to_string(), EntryClass::Person.to_string()),
            //     ProtoFilter::Eq(Attribute::Class.to_string(), EntryClass::Account.to_string()),
            //     ProtoFilter::SelfUuid,
            // ]))
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::RadiusSecret.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UserAuthTokenSession.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::RadiusSecret.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DeviceKeys.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACCOUNT_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_self_account_acp_write")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACCOUNT_SELF_ACP_WRITE_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for self write - required for accounts to update their own session state.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            // Value::JsonFilt(ProtoFilter::And(vec![
            //     match_class_filter!(EntryClass::Account).clone(),
            //     ProtoFilter::SelfUuid,
            // ]))
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_people_self_acp_write_mail")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for self write of mail for people accounts.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            // Value::JsonFilt(ProtoFilter::And(vec![
            //     match_class_filter!(EntryClass::Person).clone(),
            //     match_class_filter!(EntryClass::Account).clone(),
            //     ProtoFilter::SelfUuid,
            // ]))
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ALL_ACP_READ_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_all_acp_read")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ALL_ACP_READ_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for all read - e.g. anonymous and all authenticated accounts.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            // Value::JsonFilt(ProtoFilter::And(vec![
            //     ProtoFilter::Or(vec![
            //         match_class_filter!(EntryClass::Account),
            //         match_class_filter!(EntryClass::Group),

            //         ]),
            //     ProtoFilter::AndNot(Box::new(
            //         ProtoFilter::Or(vec![
            //             match_class_filter!(EntryClass::Tombstone),
            //             match_class_filter!(EntryClass::Recycled),
            //         ])
            //     )),
            // ]))
            Value::new_json_filter_s(
                "{\"and\":
                     [{\"or\":
                         [{\"eq\": [\"class\",\"account\"]},
                          {\"eq\": [\"class\",\"group\"]}]
                      },
                     {\"andnot\":
                         {\"or\":
                             [{\"eq\": [\"class\", \"tombstone\"]},
                              {\"eq\": [\"class\", \"recycled\"]}
                             ]
                         }
                     }
                 ]}"
            )
                .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DynMember.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SshPublicKey.to_value())
    );
}

lazy_static! {


    pub static ref FILTER_HP: ProtoFilter = ProtoFilter::Eq(
        Attribute::MemberOf.to_string(),
        UUID_IDM_HIGH_PRIVILEGE.to_string()
    );

    pub static ref FILTER_HP_OR_RECYCLED_OR_TOMBSTONE: ProtoFilter = ProtoFilter::Or(vec![
        FILTER_HP.clone(),
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ]);

    pub static ref E_IDM_ACP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_READ_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for reading personal sensitive data.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_READ_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::JsonFilt(ProtoFilter::And(vec![
                match_class_filter!(EntryClass::Person).clone(),
                ProtoFilter::AndNot(Box::new(
                    FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone()
                )),
            ]))
            // Value::new_json_filter_s(
            //     "{\"and\": [
            //         {\"eq\": [\"class\",\"person\"]},
            //         {\"andnot\":
            //             {\"or\":
            //                 [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]},
            //                 {\"eq\": [\"class\", \"tombstone\"]},
            //                 {\"eq\": [\"class\", \"recycled\"]}
            //                 ]
            //             }
            //         }
            //     ]}"
            // )
            // .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for managing personal and sensitive data.")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_WRITE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                r#"{"and": [
                    {"eq": ["class","person"]},
                    {"andnot":
                        {"or": [
                            {"eq": ["memberof","00000000-0000-0000-0000-000000001000"]},
                            {"eq": ["class", "tombstone"]},
                            {"eq": ["class", "recycled"]}
                        ]}
                    }
                ]}"#
            )
            .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (
            ATTR_ACP_MODIFY_REMOVEDATTR,
            Attribute::DisplayName.to_value()
        ),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (
            ATTR_ACP_MODIFY_PRESENTATTR,
            Attribute::DisplayName.to_value()
        ),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for creating person (user) accounts")
        ),
        (
            ATTR_ACP_RECEIVER_GROUP,
            Value::Refer(UUID_IDM_PEOPLE_MANAGE_PRIV)
        ),
        (
            ATTR_ACP_TARGET_SCOPE,
            Value::new_json_filter_s(
                r#"{"and": [
                    {"eq": ["class","account"]},
                    {"eq": ["class","person"]},
                    {"andnot":
                        {"or": [
                            {"eq": ["memberof","00000000-0000-0000-0000-000000001000"]},
                            {"eq": ["class", "tombstone"]}, {"eq": ["class", "recycled"]}
                        ]}
                    }
                ]}"#
            )
            .expect("Invalid JSON filter")
        ),
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::LegalName.to_value()),
        (
            ATTR_ACP_CREATE_ATTR,
            Attribute::PrimaryCredential.to_value()
        ),
        (ATTR_ACP_CREATE_ATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Account.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Person.to_value())
    );
}

// 31 - password import modification priv
// right now, create requires you to have access to every attribute in a single snapshot,
// so people will need to two step (create then import pw). Later we could add another
// acp that allows the create here too? Should it be separate?
lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_account_password_import_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PasswordImport.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PasswordImport.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_people_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::Person.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_people_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_READ_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (
            ATTR_NAME,
            Value::new_iname("idm_acp_account_mail_read_priv")
        ),
        (
            ATTR_UUID,
            Value::Uuid(UUID_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1)
        ),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_people_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_people_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LegalName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::Person.to_value())
    );
}

// -- end people

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_group_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_GROUP_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DynMember.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Member.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Member.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::ApiTokenSession.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::ApiTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UserAuthTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::IdVerificationEcKey.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::ApiTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Mail.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DeviceKeys.to_value()),

        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Account.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::ServiceAccount.to_value())
    );
}

// 14 radius read acp JSON_IDM_RADIUS_SERVERS_V1
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_radius_secret_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::RadiusSecret.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_radius_secret_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::RadiusSecret.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::RadiusSecret.to_value())

    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SERVERS_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_radius_servers")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_RADIUS_SERVERS_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::RadiusSecret.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_read_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::MemberOf.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::ApiTokenSession.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::ApiTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UserAuthTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::IdVerificationEcKey.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::ApiTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_group_write_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DynMember.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Member.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Member.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_schema_write_attrs_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Index.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Unique.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::MultiValue.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AttributeName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Syntax.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),

        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Index.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Unique.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::MultiValue.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Syntax.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Index.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Unique.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::MultiValue.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Syntax.to_value()),

        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Index.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Unique.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::MultiValue.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AttributeName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Syntax.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Uuid.to_value()),

        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::AttributeType.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_acp_manage_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACP_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpEnable.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpTargetScope.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpModifyClass.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpCreateClass.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AcpCreateAttr.to_value()),

        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpEnable.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpTargetScope.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpModifyClass.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpCreateClass.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AcpCreateAttr.to_value()),

        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpEnable.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpTargetScope.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpModifyClass.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpCreateClass.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AcpCreateAttr.to_value()),

        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpEnable.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpReceiverGroup.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpTargetScope.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpSearchAttr.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpModifyRemovedAttr.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpModifyPresentAttr.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpModifyClass.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpCreateClass.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AcpCreateAttr.to_value()),


        (ATTR_ACP_MODIFY_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::AccessControlDelete.to_value()),

        (ATTR_ACP_CREATE_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::AccessControlDelete.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_schema_write_classes_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::ClassName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SystemMay.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::May.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SystemMust.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Must.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::May.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Must.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::May.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Must.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::ClassName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::May.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Must.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::ClassType.to_value())
    );
}

// 21 - anonymous / everyone schema read.

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_group_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Group.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::PrimaryCredential.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::SshPublicKey.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AccountExpire.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::AccountValidFrom.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::PassKeys.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DeviceKeys.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Account.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::ServiceAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_group_manage")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Group.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_DOMAIN_ADMIN_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_domain_admin_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_DOMAIN_ADMIN_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DomainDisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DomainName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DomainLdapBasedn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DomainSsid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DomainUuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::FernetPrivateKeyStr.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::CookiePrivateKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DomainDisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DomainSsid.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DomainLdapBasedn.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::CookiePrivateKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::FernetPrivateKeyStr.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DomainDisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DomainLdapBasedn.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DomainSsid.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SYSTEM_CONFIG_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_system_config_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SYSTEM_CONFIG_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::BadlistPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::BadlistPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::BadlistPassword.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_system_config_session_exp_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("Builtin IDM Control for granting session expiry configuration rights")
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
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("class")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("name")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("uuid")),
        (ATTR_ACP_SEARCH_ATTR, Value::new_iutf8("description")),
        (ATTR_ACP_SEARCH_ATTR, Attribute::AuthSessionExpiry.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::AuthSessionExpiry.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::AuthSessionExpiry.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::PrivilegeExpiry.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::PrivilegeExpiry.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::PrivilegeExpiry.to_value())

    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_account_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::PosixAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_group_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::PosixGroup.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_account_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::LoginShell.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::UnixPassword.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::PosixAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_group_unix_extend_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::DynMember.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Spn.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Member.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::GidNumber.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::PosixGroup.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_oauth2_manage_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsName.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsBasicSecret.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2RsTokenKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Rs256PrivateKeyDer.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::OAuth2PreferShortUsername.to_value()),

        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsName.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsBasicSecret.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2RsTokenKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Es256PrivateKeyDer.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Rs256PrivateKeyDer.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::OAuth2PreferShortUsername.to_value()),


        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2RsName.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::OAuth2PreferShortUsername.to_value()),

        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::DisplayName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2RsName.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2RsOrigin.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2RsOriginLanding.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2RsSupScopeMap.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2RsScopeMap.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::OAuth2PreferShortUsername.to_value()),


        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::OAuth2ResourceServer.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::OAuth2ResourceServerBasic.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::OAuth2ResourceServerPublic.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_hp_acp_service_account_into_person_migrate")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Class.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::ServiceAccount.to_value()),
        (ATTR_ACP_MODIFY_CLASS, EntryClass::Person.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (ATTR_CLASS, EntryClass::Object.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlProfile.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlCreate.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlDelete.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlModify.to_value()),
        (ATTR_CLASS, EntryClass::AccessControlSearch.to_value()),
        (ATTR_NAME, Value::new_iname("idm_acp_hp_sync_account_manage_priv")),
        (ATTR_UUID, Value::Uuid(UUID_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1)),
        (
            Attribute::Description.as_ref(),
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
        (ATTR_ACP_SEARCH_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Uuid.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::JwsEs256PrivateKey.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SyncTokenSession.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SyncCredentialPortal.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SyncYieldAuthority.to_value()),
        (ATTR_ACP_SEARCH_ATTR, Attribute::SyncCookie.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::JwsEs256PrivateKey.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SyncTokenSession.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SyncCredentialPortal.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SyncCookie.to_value()),
        (ATTR_ACP_MODIFY_REMOVEDATTR, Attribute::SyncYieldAuthority.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Name.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::Description.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::SyncTokenSession.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::SyncCredentialPortal.to_value()),
        (ATTR_ACP_MODIFY_PRESENTATTR, Attribute::SyncYieldAuthority.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Class.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Name.to_value()),
        (ATTR_ACP_CREATE_ATTR, Attribute::Description.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::Object.to_value()),
        (ATTR_ACP_CREATE_CLASS, EntryClass::SyncAccount.to_value())
    );
}
