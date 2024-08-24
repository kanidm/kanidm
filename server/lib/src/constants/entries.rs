//! Constant Entries for the IDM
use std::fmt::Display;

use crate::constants::groups::idm_builtin_admin_groups;
use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::idm::account::Account;
use crate::value::PartialValue;
use crate::value::Value;
pub use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::*;
use kanidm_proto::internal::OperationError;
use kanidm_proto::v1::AccountType;

use uuid::Uuid;

#[derive(Copy, Clone, Debug)]
pub enum EntryClass {
    AccessControlCreate,
    AccessControlDelete,
    AccessControlModify,
    AccessControlProfile,
    AccessControlReceiverEntryManager,
    AccessControlReceiverGroup,
    AccessControlSearch,
    AccessControlTargetScope,
    Account,
    AccountPolicy,
    Application,
    AttributeType,
    Builtin,
    Class,
    ClassType,
    ClientCertificate,
    Conflict,
    DomainInfo,
    DynGroup,
    ExtensibleObject,
    Group,
    KeyProvider,
    KeyProviderInternal,
    KeyObject,
    KeyObjectJwtEs256,
    KeyObjectJweA128GCM,
    KeyObjectInternal,
    MemberOf,
    OAuth2ResourceServer,
    OAuth2ResourceServerBasic,
    OAuth2ResourceServerPublic,
    Object,
    OrgPerson,
    Person,
    PosixAccount,
    PosixGroup,
    Recycled,
    Service,
    ServiceAccount,
    SyncAccount,
    SyncObject,
    Tombstone,
    User,
    System,
    SystemInfo,
    SystemConfig,
    #[cfg(any(test, debug_assertions))]
    TestClass,
}

impl From<EntryClass> for &'static str {
    fn from(val: EntryClass) -> Self {
        match val {
            EntryClass::AccessControlCreate => "access_control_create",
            EntryClass::AccessControlDelete => "access_control_delete",
            EntryClass::AccessControlModify => "access_control_modify",
            EntryClass::AccessControlProfile => "access_control_profile",
            EntryClass::AccessControlReceiverEntryManager => {
                "access_control_receiver_entry_manager"
            }
            EntryClass::AccessControlReceiverGroup => "access_control_receiver_group",
            EntryClass::AccessControlSearch => "access_control_search",
            EntryClass::AccessControlTargetScope => "access_control_target_scope",
            EntryClass::Account => "account",
            EntryClass::AccountPolicy => "account_policy",
            EntryClass::Application => "application",
            EntryClass::AttributeType => "attributetype",
            EntryClass::Builtin => ENTRYCLASS_BUILTIN,
            EntryClass::Class => ATTR_CLASS,
            EntryClass::ClassType => "classtype",
            EntryClass::ClientCertificate => "client_certificate",
            EntryClass::Conflict => "conflict",
            EntryClass::DomainInfo => "domain_info",
            EntryClass::DynGroup => ATTR_DYNGROUP,
            EntryClass::ExtensibleObject => "extensibleobject",
            EntryClass::Group => ATTR_GROUP,
            EntryClass::KeyProvider => ENTRYCLASS_KEY_PROVIDER,
            EntryClass::KeyProviderInternal => ENTRYCLASS_KEY_PROVIDER_INTERNAL,
            EntryClass::KeyObject => ENTRYCLASS_KEY_OBJECT,
            EntryClass::KeyObjectJwtEs256 => ENTRYCLASS_KEY_OBJECT_JWT_ES256,
            EntryClass::KeyObjectJweA128GCM => ENTRYCLASS_KEY_OBJECT_JWE_A128GCM,
            EntryClass::KeyObjectInternal => ENTRYCLASS_KEY_OBJECT_INTERNAL,
            EntryClass::MemberOf => "memberof",
            EntryClass::OAuth2ResourceServer => "oauth2_resource_server",
            EntryClass::OAuth2ResourceServerBasic => "oauth2_resource_server_basic",
            EntryClass::OAuth2ResourceServerPublic => "oauth2_resource_server_public",
            EntryClass::Object => "object",
            EntryClass::OrgPerson => "orgperson",
            EntryClass::Person => "person",
            EntryClass::PosixAccount => "posixaccount",
            EntryClass::PosixGroup => "posixgroup",
            EntryClass::Recycled => "recycled",
            EntryClass::Service => "service",
            EntryClass::ServiceAccount => "service_account",
            EntryClass::SyncAccount => "sync_account",
            EntryClass::SyncObject => "sync_object",
            EntryClass::System => "system",
            EntryClass::SystemConfig => "system_config",
            EntryClass::SystemInfo => "system_info",
            EntryClass::Tombstone => "tombstone",
            #[cfg(any(test, debug_assertions))]
            EntryClass::TestClass => "testclass",
            EntryClass::User => "user",
        }
    }
}

impl AsRef<str> for EntryClass {
    fn as_ref(&self) -> &str {
        self.into()
    }
}

impl From<&EntryClass> for &'static str {
    fn from(value: &EntryClass) -> Self {
        (*value).into()
    }
}

impl From<EntryClass> for String {
    fn from(val: EntryClass) -> Self {
        let s: &'static str = val.into();
        s.to_string()
    }
}

impl From<EntryClass> for Value {
    fn from(val: EntryClass) -> Self {
        Value::new_iutf8(val.into())
    }
}

impl From<EntryClass> for PartialValue {
    fn from(val: EntryClass) -> Self {
        PartialValue::new_iutf8(val.into())
    }
}

impl From<EntryClass> for crate::prelude::AttrString {
    fn from(val: EntryClass) -> Self {
        crate::prelude::AttrString::from(val.to_string())
    }
}

impl Display for EntryClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = (*self).into();
        write!(f, "{}", s)
    }
}

impl EntryClass {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_partialvalue(self) -> PartialValue {
        let s: &'static str = self.into();
        PartialValue::new_iutf8(s)
    }

    /// Return a filter that'll match this class
    pub fn as_f_eq(&self) -> crate::filter::FC {
        crate::filter::f_eq(Attribute::Class, self.to_partialvalue())
    }
}

lazy_static! {
    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_IDM_ADMIN: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        entry_managed_by: None,
        name: "idm_admin",
        uuid: UUID_IDM_ADMIN,
        description: "Builtin IDM Admin account.",
        displayname: "IDM Administrator",
    };

    pub static ref E_SYSTEM_INFO_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::SystemInfo.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Uuid, Value::Uuid(UUID_SYSTEM_INFO)),
        (
            Attribute::Description,
            Value::new_utf8s("System (local) info and metadata object.")
        ),
        (Attribute::Version, Value::Uint32(20))
    );

    pub static ref E_DOMAIN_INFO_DL6: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::DomainInfo.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Class, EntryClass::KeyObject.to_value()),
        (Attribute::Class, EntryClass::KeyObjectJwtEs256.to_value()),
        (Attribute::Class, EntryClass::KeyObjectJweA128GCM.to_value()),
        (Attribute::Name, Value::new_iname("domain_local")),
        (Attribute::Uuid, Value::Uuid(UUID_DOMAIN_INFO)),
        (
            Attribute::Description,
            Value::new_utf8s("This local domain's info and metadata object.")
        )
    );
}

#[derive(Debug, Clone)]
/// Built in accounts such as anonymous, idm_admin and admin
pub struct BuiltinAccount {
    pub account_type: kanidm_proto::v1::AccountType,
    pub entry_managed_by: Option<uuid::Uuid>,
    pub name: &'static str,
    pub uuid: Uuid,
    pub description: &'static str,
    pub displayname: &'static str,
}

impl Default for BuiltinAccount {
    fn default() -> Self {
        BuiltinAccount {
            account_type: AccountType::ServiceAccount,
            entry_managed_by: None,
            name: "",
            uuid: Uuid::new_v4(),
            description: "<set description>",
            displayname: "<set displayname>",
        }
    }
}

impl From<BuiltinAccount> for Account {
    fn from(value: BuiltinAccount) -> Self {
        #[allow(clippy::panic)]
        if value.uuid >= DYNAMIC_RANGE_MINIMUM_UUID {
            panic!("Builtin ACP has invalid UUID! {:?}", value);
        }
        Account {
            name: value.name.to_string(),
            uuid: value.uuid,
            displayname: value.displayname.to_string(),
            spn: format!("{}@example.com", value.name),
            mail_primary: None,
            mail: Vec::with_capacity(0),
            ..Default::default()
        }
    }
}

impl From<BuiltinAccount> for EntryInitNew {
    fn from(value: BuiltinAccount) -> Self {
        let mut entry = EntryInitNew::new();
        entry.add_ava(Attribute::Name, Value::new_iname(value.name));
        #[allow(clippy::panic)]
        if value.uuid >= DYNAMIC_RANGE_MINIMUM_UUID {
            panic!("Builtin ACP has invalid UUID! {:?}", value);
        }
        entry.add_ava(Attribute::Uuid, Value::Uuid(value.uuid));
        entry.add_ava(Attribute::Description, Value::new_utf8s(value.description));
        entry.add_ava(Attribute::DisplayName, Value::new_utf8s(value.displayname));

        if let Some(entry_manager) = value.entry_managed_by {
            entry.add_ava(Attribute::EntryManagedBy, Value::Refer(entry_manager));
        }

        entry.set_ava(
            Attribute::Class,
            vec![
                EntryClass::Account.to_value(),
                EntryClass::MemberOf.to_value(),
                EntryClass::Object.to_value(),
            ],
        );
        match value.account_type {
            AccountType::Person => entry.add_ava(Attribute::Class, EntryClass::Person.to_value()),
            AccountType::ServiceAccount => {
                entry.add_ava(Attribute::Class, EntryClass::ServiceAccount.to_value())
            }
        }
        entry
    }
}

lazy_static! {
    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_ADMIN: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        entry_managed_by: None,
        name: "admin",
        uuid: UUID_ADMIN,
        description: "Builtin System Admin account.",
        displayname: "System Administrator",
    };
}

lazy_static! {
    pub static ref BUILTIN_ACCOUNT_ANONYMOUS_DL6: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        entry_managed_by: Some(UUID_IDM_ADMINS),
        name: "anonymous",
        uuid: UUID_ANONYMOUS,
        description: "Anonymous access account.",
        displayname: "Anonymous",
    };
}

pub fn builtin_accounts() -> Vec<&'static BuiltinAccount> {
    vec![
        &BUILTIN_ACCOUNT_ADMIN,
        &BUILTIN_ACCOUNT_IDM_ADMIN,
        &BUILTIN_ACCOUNT_ANONYMOUS_DL6,
    ]
}

// ============ TEST DATA ============
#[cfg(test)]
pub const UUID_TESTPERSON_1: Uuid = ::uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

#[cfg(test)]
pub const UUID_TESTPERSON_2: Uuid = ::uuid::uuid!("538faac7-4d29-473b-a59d-23023ac19955");

#[cfg(test)]
lazy_static! {
    pub static ref E_TESTPERSON_1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("Test Person 1")),
        (Attribute::Uuid, Value::Uuid(UUID_TESTPERSON_1))
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson2")),
        (Attribute::DisplayName, Value::new_utf8s("Test Person 2")),
        (Attribute::Uuid, Value::Uuid(UUID_TESTPERSON_2))
    );
}

// ⚠️  DOMAIN LEVEL 1 ENTRIES ⚠️
// Future entries need to be added via migrations.
//
// DO NOT MODIFY THIS DEFINITION

/// Build a list of internal admin entries
pub fn idm_builtin_admin_entries() -> Result<Vec<EntryInitNew>, OperationError> {
    let mut res: Vec<EntryInitNew> = vec![
        BUILTIN_ACCOUNT_ADMIN.clone().into(),
        BUILTIN_ACCOUNT_IDM_ADMIN.clone().into(),
    ];
    for group in idm_builtin_admin_groups() {
        let g: EntryInitNew = group.clone().try_into()?;
        res.push(g);
    }

    // We need to push anonymous *after* groups due to entry-managed-by
    res.push(BUILTIN_ACCOUNT_ANONYMOUS_DL6.clone().into());

    Ok(res)
}
