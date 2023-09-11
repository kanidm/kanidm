#![allow(clippy::expect_used)]
//! Constant Entries for the IDM

use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::prelude::*;
use crate::value::Value;
use kanidm_proto::v1::Filter as ProtoFilter;

lazy_static! {
    pub static ref DEFAULT_TARGET_SCOPE: ProtoFilter = ProtoFilter::And(Vec::with_capacity(0));
}

#[derive(Clone, Debug)]
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
            target_scope: DEFAULT_TARGET_SCOPE.clone(), // evals to matching nothing
        }
    }
}

impl From<BuiltinAcp> for EntryInitNew {
    fn from(value: BuiltinAcp) -> Self {
        let mut entry = EntryInitNew::default();

        #[allow(clippy::panic)]
        if value.name.is_empty() {
            panic!("Builtin ACP has no name! {:?}", value);
        }
        #[allow(clippy::panic)]
        if value.classes.is_empty() {
            panic!("Builtin ACP has no classes! {:?}", value);
        }
        #[allow(clippy::panic)]
        if DEFAULT_TARGET_SCOPE.clone() == value.target_scope {
            panic!("Builtin ACP has an invalid target_scope! {:?}", value);
        }

        value.classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::Class, class.to_value());
        });

        entry.set_ava(Attribute::Name, [Value::new_iname(value.name)]);
        entry.set_ava(Attribute::Uuid, [Value::Uuid(value.uuid)]);
        entry.set_ava(
            Attribute::Description,
            [Value::new_utf8s(value.description)],
        );
        entry.set_ava(
            Attribute::AcpReceiverGroup,
            [Value::Refer(value.receiver_group)],
        );
        entry.set_ava(
            Attribute::AcpTargetScope,
            [Value::JsonFilt(value.target_scope)],
        );

        entry.set_ava(
            Attribute::AcpSearchAttr,
            value
                .search_attrs
                .into_iter()
                .map(|sa| sa.to_value())
                .collect::<Vec<Value>>(),
        );
        value.modify_removed_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyRemovedAttr, attr.to_value());
        });
        value.modify_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyClass, class.to_value());
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
        target_scope: ProtoFilter::Eq(Attribute::Class.to_string(), ATTR_RECYCLED.to_string()),

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
        target_scope: ProtoFilter::Eq(Attribute::Class.to_string(), ATTR_RECYCLED.to_string()),
        modify_removed_attrs: vec![Attribute::Class],
        search_attrs: vec![],
        modify_classes: vec![EntryClass::Recycled],
    };
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_READ_V1: EntryInitNew =
        entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_self_acp_read")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_SELF_ACP_READ_V1)),
        (
            Attribute::Description,
            Value::new_utf8s(
                "Builtin IDM Control for self read - required for whoami and many other functions"
            )
        ),
        (Attribute::AcpReceiverGroup, Value::Refer(UUID_IDM_ALL_ACCOUNTS)),
        (
            Attribute::AcpTargetScope,
            Value::JsonFilt(ProtoFilter::SelfUuid)
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::MemberOf.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Mail.to_value()),
        (Attribute::AcpSearchAttr, Attribute::RadiusSecret.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SyncParentUuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpSearchAttr, Attribute::PrimaryCredential.to_value()),
        (
            Attribute::AcpSearchAttr,
            Attribute::UserAuthTokenSession.to_value()
        ),
        (Attribute::AcpSearchAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DeviceKeys.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_self_acp_write")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_SELF_ACP_WRITE_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ALL_PERSONS)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::RadiusSecret.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::UserAuthTokenSession.to_value()),

        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::RadiusSecret.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DeviceKeys.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACCOUNT_SELF_ACP_WRITE_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_self_account_acp_write")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACCOUNT_SELF_ACP_WRITE_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for self write - required for accounts to update their own session state.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            Attribute::AcpTargetScope,
            // Value::JsonFilt(ProtoFilter::And(vec![
            //     match_class_filter!(EntryClass::Account).clone(),
            //     ProtoFilter::SelfUuid,
            // ]))
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, \"self\"]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_people_self_acp_write_mail")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for self write of mail for people accounts.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpModifyRemovedAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ALL_ACP_READ_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_all_acp_read")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ALL_ACP_READ_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for all read - e.g. anonymous and all authenticated accounts.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ALL_ACCOUNTS)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::MemberOf.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Member.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DynMember.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SshPublicKey.to_value())
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
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_people_read_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_PEOPLE_READ_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for reading personal sensitive data.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_PEOPLE_READ_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (
            Attribute::Class,
            EntryClass::AccessControlProfile.to_value()
        ),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (
            Attribute::Name,
            Value::new_iname("idm_acp_people_write_priv")
        ),
        (
            Attribute::Uuid,
            Value::Uuid(UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1)
        ),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing personal and sensitive data.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_PEOPLE_WRITE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (
            Attribute::AcpModifyRemovedAttr,
            Attribute::DisplayName.to_value()
        ),
        (
            Attribute::AcpModifyRemovedAttr,
            Attribute::LegalName.to_value()
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (
            Attribute::AcpModifyPresentAttr,
            Attribute::DisplayName.to_value()
        ),
        (
            Attribute::AcpModifyPresentAttr,
            Attribute::LegalName.to_value()
        ),
        (Attribute::AcpModifyPresentAttr, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (
            Attribute::Class,
            EntryClass::AccessControlProfile.to_value()
        ),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_people_manage")),
        (
            Attribute::Uuid,
            Value::Uuid(UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1)
        ),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for creating person (user) accounts")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_PEOPLE_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::LegalName.to_value()),
        (
            Attribute::AcpCreateAttr,
            Attribute::PrimaryCredential.to_value()
        ),
        (Attribute::AcpCreateAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Mail.to_value()),
        (
            Attribute::AcpCreateAttr,
            Attribute::AccountExpire.to_value()
        ),
        (
            Attribute::AcpCreateAttr,
            Attribute::AccountValidFrom.to_value()
        ),
        (Attribute::AcpCreateAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Account.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Person.to_value())
    );
}

// 31 - password import modification priv
// right now, create requires you to have access to every attribute in a single snapshot,
// so people will need to two step (create then import pw). Later we could add another
// acp that allows the create here too? Should it be separate?
lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_people_account_password_import_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for allowing imports of passwords to people+account types.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::PasswordImport.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PasswordImport.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_people_extend_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for allowing person class extension")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_PEOPLE_EXTEND_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyClass, EntryClass::Person.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_READ_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (
            Attribute::Class,
            EntryClass::AccessControlProfile.to_value()
        ),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (
            Attribute::Name,
            Value::new_iname("idm_acp_hp_people_read_priv")
        ),
        (
            Attribute::Uuid,
            Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_READ_PRIV_V1)
        ),
        (
            Attribute::Description,
            Value::new_utf8s(
                "Builtin IDM Control for reading high privilege personal sensitive data."
            )
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_PEOPLE_READ_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
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
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (
            Attribute::Name,
            Value::new_iname("idm_acp_account_mail_read_priv")
        ),
        (
            Attribute::Uuid,
            Value::Uuid(UUID_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1)
        ),
        (
            Attribute::Description,
            Value::new_utf8s(
                "Builtin IDM Control for reading account mail attributes."
            )
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ACCOUNT_MAIL_READ_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s("{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}")
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Mail.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_people_write_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing privilege personal and sensitive data.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_PEOPLE_WRITE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"person\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_people_extend_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for allowing privilege person class extension")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_PEOPLE_EXTEND_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::LegalName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyClass, EntryClass::Person.to_value())
    );
}

// -- end people

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_group_write_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_GROUP_WRITE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing groups")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_GROUP_WRITE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Member.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DynMember.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Member.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Member.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_account_read_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for reading accounts.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ACCOUNT_READ_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpSearchAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpSearchAttr, Attribute::MemberOf.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Mail.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpSearchAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpSearchAttr, Attribute::ApiTokenSession.to_value()),
        (Attribute::AcpSearchAttr, Attribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_account_write_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing all accounts (both person and service).")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ACCOUNT_WRITE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::ApiTokenSession.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::UserAuthTokenSession.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::IdVerificationEcKey.to_value()),

        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Mail.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::ApiTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_account_manage")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for creating and deleting (service) accounts")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ACCOUNT_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpCreateAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Mail.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpCreateAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DeviceKeys.to_value()),

        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Account.to_value()),
        (Attribute::AcpCreateClass, EntryClass::ServiceAccount.to_value())
    );
}

// 14 radius read acp JSON_IDM_RADIUS_SERVERS_V1
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_radius_secret_read_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for reading user radius secrets.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_RADIUS_SECRET_READ_PRIV_V1)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::RadiusSecret.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_radius_secret_write_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control allowing writes to user radius secrets.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::RadiusSecret.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::RadiusSecret.to_value())

    );
}

lazy_static! {
    pub static ref E_IDM_ACP_RADIUS_SERVERS_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_radius_servers")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_RADIUS_SERVERS_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for RADIUS servers to read credentials and other needed details.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_RADIUS_SERVERS)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
            "{\"and\": [{\"pres\": \"class\"}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::RadiusSecret.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_account_read_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for reading high privilege accounts.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_ACCOUNT_READ_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpSearchAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpSearchAttr, Attribute::MemberOf.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpSearchAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpSearchAttr, Attribute::ApiTokenSession.to_value()),
        (Attribute::AcpSearchAttr, Attribute::UserAuthTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_account_write_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing high privilege accounts (both person and service).")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_ACCOUNT_WRITE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::ApiTokenSession.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::UserAuthTokenSession.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::IdVerificationEcKey.to_value()),

        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::ApiTokenSession.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_WRITE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_group_write_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing high privilege groups")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_GROUP_WRITE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Member.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DynMember.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Member.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Member.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_schema_write_attrs_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for management of schema attributes.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_SCHEMA_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"attributetype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Index.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Unique.to_value()),
        (Attribute::AcpSearchAttr, Attribute::MultiValue.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AttributeName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Syntax.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),

        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Index.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Unique.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::MultiValue.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Syntax.to_value()),

        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Index.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Unique.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::MultiValue.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Syntax.to_value()),

        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Index.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Unique.to_value()),
        (Attribute::AcpCreateAttr, Attribute::MultiValue.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AttributeName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Syntax.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Uuid.to_value()),

        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::AttributeType.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_acp_manage_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_ACP_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for access profiles management.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ACP_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"access_control_profile\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpEnable.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpReceiverGroup.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpTargetScope.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpSearchAttr.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpModifyRemovedAttr.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpModifyPresentAttr.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpModifyClass.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpCreateClass.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AcpCreateAttr.to_value()),

        (Attribute::AcpModifyRemovedAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpEnable.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpReceiverGroup.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpTargetScope.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpSearchAttr.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpModifyRemovedAttr.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpModifyPresentAttr.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpModifyClass.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpCreateClass.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AcpCreateAttr.to_value()),

        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpEnable.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpReceiverGroup.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpTargetScope.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpSearchAttr.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpModifyRemovedAttr.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpModifyPresentAttr.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpModifyClass.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpCreateClass.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AcpCreateAttr.to_value()),

        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpEnable.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpReceiverGroup.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpTargetScope.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpSearchAttr.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpModifyRemovedAttr.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpModifyPresentAttr.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpModifyClass.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpCreateClass.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AcpCreateAttr.to_value()),


        (Attribute::AcpModifyClass, EntryClass::AccessControlProfile.to_value()),
        (Attribute::AcpModifyClass, EntryClass::AccessControlSearch.to_value()),
        (Attribute::AcpModifyClass, EntryClass::AccessControlModify.to_value()),
        (Attribute::AcpModifyClass, EntryClass::AccessControlCreate.to_value()),
        (Attribute::AcpModifyClass, EntryClass::AccessControlDelete.to_value()),

        (Attribute::AcpCreateClass, EntryClass::AccessControlProfile.to_value()),
        (Attribute::AcpCreateClass, EntryClass::AccessControlSearch.to_value()),
        (Attribute::AcpCreateClass, EntryClass::AccessControlModify.to_value()),
        (Attribute::AcpCreateClass, EntryClass::AccessControlCreate.to_value()),
        (Attribute::AcpCreateClass, EntryClass::AccessControlDelete.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_schema_write_classes_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for management of schema classes.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_SCHEMA_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"classtype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::ClassName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SystemMay.to_value()),
        (Attribute::AcpSearchAttr, Attribute::May.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SystemMust.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Must.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::May.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Must.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::May.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Must.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::ClassName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::May.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Must.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::ClassType.to_value())
    );
}

// 21 - anonymous / everyone schema read.

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_group_manage")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for creating and deleting groups in the directory")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_GROUP_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Member.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Group.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_account_manage")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for creating and deleting hp and regular (service) accounts")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_ACCOUNT_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
            "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::PrimaryCredential.to_value()),
        (Attribute::AcpCreateAttr, Attribute::SshPublicKey.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AccountExpire.to_value()),
        (Attribute::AcpCreateAttr, Attribute::AccountValidFrom.to_value()),
        (Attribute::AcpCreateAttr, Attribute::PassKeys.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DeviceKeys.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Account.to_value()),
        (Attribute::AcpCreateClass, EntryClass::ServiceAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_group_manage")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for creating and deleting hp and regular groups in the directory")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_GROUP_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Member.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Group.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_DOMAIN_ADMIN_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_domain_admin_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_DOMAIN_ADMIN_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for granting domain info administration locally")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_DOMAIN_ADMINS)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000025\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DomainDisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DomainName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DomainLdapBasedn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DomainSsid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DomainUuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Es256PrivateKeyDer.to_value()),
        (Attribute::AcpSearchAttr, Attribute::FernetPrivateKeyStr.to_value()),
        (Attribute::AcpSearchAttr, Attribute::CookiePrivateKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DomainDisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DomainSsid.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DomainLdapBasedn.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Es256PrivateKeyDer.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::CookiePrivateKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::FernetPrivateKeyStr.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DomainDisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DomainLdapBasedn.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DomainSsid.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SYSTEM_CONFIG_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_system_config_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_SYSTEM_CONFIG_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for granting system configuration rights")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_SYSTEM_ADMINS)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::BadlistPassword.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::BadlistPassword.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::BadlistPassword.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_system_config_session_exp_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for granting session expiry configuration rights")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_SYSTEM_ADMINS)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::AuthSessionExpiry.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::AuthSessionExpiry.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::AuthSessionExpiry.to_value()),
        (Attribute::AcpSearchAttr, Attribute::PrivilegeExpiry.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::PrivilegeExpiry.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::PrivilegeExpiry.to_value())

    );
}

lazy_static! {
    pub static ref E_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_account_unix_extend_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing and extending unix accounts")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpSearchAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyClass, EntryClass::PosixAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_group_unix_extend_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing and extending unix groups")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_GROUP_UNIX_EXTEND_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Member.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyClass, EntryClass::PosixGroup.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_account_unix_extend_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing and extending unix accounts")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpSearchAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpSearchAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::LoginShell.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::UnixPassword.to_value()),
        (Attribute::AcpModifyClass, EntryClass::PosixAccount.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_group_unix_extend_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing and extending unix high privilege groups")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::DynMember.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Spn.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Member.to_value()),
        (Attribute::AcpSearchAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::GidNumber.to_value()),
        (Attribute::AcpModifyClass, EntryClass::PosixGroup.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_oauth2_manage_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing oauth2 resource server integrations.")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_OAUTH2_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"oauth2_resource_server\"]},{\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsName.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsOrigin.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsOriginLanding.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsScopeMap.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsSupScopeMap.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsBasicSecret.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2RsTokenKey.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Es256PrivateKeyDer.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Rs256PrivateKeyDer.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (Attribute::AcpSearchAttr, Attribute::OAuth2PreferShortUsername.to_value()),

        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsName.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsOrigin.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsOriginLanding.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsScopeMap.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsSupScopeMap.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsBasicSecret.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2RsTokenKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Es256PrivateKeyDer.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Rs256PrivateKeyDer.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::OAuth2PreferShortUsername.to_value()),


        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2RsName.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2RsOrigin.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2RsOriginLanding.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2RsSupScopeMap.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2RsScopeMap.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::OAuth2PreferShortUsername.to_value()),

        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateAttr, Attribute::DisplayName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2RsName.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2RsOrigin.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2RsOriginLanding.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2RsSupScopeMap.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2RsScopeMap.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2AllowInsecureClientDisablePkce.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2JwtLegacyCryptoEnable.to_value()),
        (Attribute::AcpCreateAttr, Attribute::OAuth2PreferShortUsername.to_value()),


        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::OAuth2ResourceServer.to_value()),
        (Attribute::AcpCreateClass, EntryClass::OAuth2ResourceServerBasic.to_value()),
        (Attribute::AcpCreateClass, EntryClass::OAuth2ResourceServerPublic.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_hp_acp_service_account_into_person_migrate")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control allowing service accounts to be migrated into persons")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Class.to_value()),
        (Attribute::AcpModifyClass, EntryClass::ServiceAccount.to_value()),
        (Attribute::AcpModifyClass, EntryClass::Person.to_value())
    );
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::AccessControlProfile.to_value()),
        (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
        (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
        (Attribute::Class, EntryClass::AccessControlModify.to_value()),
        (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
        (Attribute::Name, Value::new_iname("idm_acp_hp_sync_account_manage_priv")),
        (Attribute::Uuid, Value::Uuid(UUID_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1)),
        (
            Attribute::Description,
            Value::new_utf8s("Builtin IDM Control for managing IDM synchronisation accounts / connections")
        ),
        (
            Attribute::AcpReceiverGroup,
            Value::Refer(UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV)
        ),
        (
            Attribute::AcpTargetScope,
            Value::new_json_filter_s(
                "{\"and\": [{\"eq\": [\"class\",\"sync_account\"]},{\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
            )
                .expect("Invalid JSON filter")
        ),
        (Attribute::AcpSearchAttr, Attribute::Class.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Uuid.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Name.to_value()),
        (Attribute::AcpSearchAttr, Attribute::Description.to_value()),
        (Attribute::AcpSearchAttr, Attribute::JwsEs256PrivateKey.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SyncTokenSession.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SyncCredentialPortal.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SyncYieldAuthority.to_value()),
        (Attribute::AcpSearchAttr, Attribute::SyncCookie.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::JwsEs256PrivateKey.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SyncTokenSession.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SyncCredentialPortal.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SyncCookie.to_value()),
        (Attribute::AcpModifyRemovedAttr, Attribute::SyncYieldAuthority.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Name.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::Description.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::SyncTokenSession.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::SyncCredentialPortal.to_value()),
        (Attribute::AcpModifyPresentAttr, Attribute::SyncYieldAuthority.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Class.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Name.to_value()),
        (Attribute::AcpCreateAttr, Attribute::Description.to_value()),
        (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
        (Attribute::AcpCreateClass, EntryClass::SyncAccount.to_value())
    );
}
