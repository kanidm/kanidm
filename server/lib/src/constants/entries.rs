//! Constant Entries for the IDM
use std::fmt::Display;

use crate::value::PartialValue;
use crate::value::Value;
use crate::valueset::{ValueSet, ValueSetIutf8};
pub use kanidm_proto::attribute::Attribute;
use kanidm_proto::constants::*;
use kanidm_proto::scim_v1::JsonValue;
use kanidm_proto::scim_v1::ScimFilter;

//TODO: This would do well in the proto lib
// together with all the other definitions.
// That way`OperationError::MissingClass` can
// Directly reference the entryclass rather
// than relying on its string name
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
    KeyObjectJwtRs256,
    KeyObjectJweA128GCM,
    KeyObjectInternal,
    MemberOf,
    OAuth2ResourceServer,
    OAuth2ResourceServerBasic,
    OAuth2ResourceServerPublic,
    OAuth2DeviceCodeSession,
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

impl From<EntryClass> for ScimFilter {
    fn from(ec: EntryClass) -> Self {
        ScimFilter::Equal(Attribute::Class.into(), ec.into())
    }
}

impl From<EntryClass> for &'static str {
    fn from(val: EntryClass) -> Self {
        match val {
            EntryClass::AccessControlCreate => ACCESS_CONTROL_CREATE,
            EntryClass::AccessControlDelete => ACCESS_CONTROL_DELETE,
            EntryClass::AccessControlModify => ACCESS_CONTROL_MODIFY,
            EntryClass::AccessControlProfile => ACCESS_CONTROL_PROFILE,
            EntryClass::AccessControlReceiverEntryManager => ACCESS_CONTROL_RECEIVER_ENTRY_MANAGER,
            EntryClass::AccessControlReceiverGroup => ACCESS_CONTROL_RECEIVER_GROUP,
            EntryClass::AccessControlSearch => ACCESS_CONTROL_SEARCH,
            EntryClass::AccessControlTargetScope => ACCESS_CONTROL_TARGET_SCOPE,
            EntryClass::Account => ENTRYCLASS_ACCOUNT,
            EntryClass::AccountPolicy => ENTRYCLASS_ACCOUNT_POLICY,
            EntryClass::Application => ENTRYCLASS_APPLICATION,
            EntryClass::AttributeType => ENTRYCLASS_ATTRIBUTE_TYPE,
            EntryClass::Builtin => ENTRYCLASS_BUILTIN,
            EntryClass::Class => ENTRYCLASS_CLASS,
            EntryClass::ClassType => ENTRYCLASS_CLASS_TYPE,
            EntryClass::ClientCertificate => ENTRYCLASS_CLIENT_CERTIFICATE,
            EntryClass::Conflict => ENTRYCLASS_CONFLICT,
            EntryClass::DomainInfo => ENTRYCLASS_DOMAIN_INFO,
            EntryClass::DynGroup => ENTRYCLASS_DYN_GROUP,
            EntryClass::ExtensibleObject => ENTRYCLASS_EXTENSIBLE_OBJECT,
            EntryClass::Group => ENTRYCLASS_GROUP,
            EntryClass::KeyProvider => ENTRYCLASS_KEY_PROVIDER,
            EntryClass::KeyProviderInternal => ENTRYCLASS_KEY_PROVIDER_INTERNAL,
            EntryClass::KeyObject => ENTRYCLASS_KEY_OBJECT,
            EntryClass::KeyObjectJwtEs256 => ENTRYCLASS_KEY_OBJECT_JWT_ES256,
            EntryClass::KeyObjectJwtRs256 => ENTRYCLASS_KEY_OBJECT_JWT_RS256,
            EntryClass::KeyObjectJweA128GCM => ENTRYCLASS_KEY_OBJECT_JWE_A128GCM,
            EntryClass::KeyObjectInternal => ENTRYCLASS_KEY_OBJECT_INTERNAL,
            EntryClass::MemberOf => ENTRYCLASS_MEMBER_OF,
            EntryClass::OAuth2DeviceCodeSession => OAUTH2_DEVICE_CODE_SESSION,
            EntryClass::OAuth2ResourceServer => OAUTH2_RESOURCE_SERVER,
            EntryClass::OAuth2ResourceServerBasic => OAUTH2_RESOURCE_SERVER_BASIC,
            EntryClass::OAuth2ResourceServerPublic => OAUTH2_RESOURCE_SERVER_PUBLIC,
            EntryClass::Object => ENTRYCLASS_OBJECT,
            EntryClass::OrgPerson => ENTRYCLASS_ORG_PERSON,
            EntryClass::Person => ENTRYCLASS_PERSON,
            EntryClass::PosixAccount => ENTRYCLASS_POSIX_ACCOUNT,
            EntryClass::PosixGroup => ENTRYCLASS_POSIX_GROUP,
            EntryClass::Recycled => ENTRYCLASS_RECYCLED,
            EntryClass::Service => ENTRYCLASS_SERVICE,
            EntryClass::ServiceAccount => ENTRYCLASS_SERVICE_ACCOUNT,
            EntryClass::SyncAccount => ENTRYCLASS_SYNC_ACCOUNT,
            EntryClass::SyncObject => ENTRYCLASS_SYNC_OBJECT,
            EntryClass::System => ENTRYCLASS_SYSTEM,
            EntryClass::SystemConfig => ENTRYCLASS_SYSTEM_CONFIG,
            EntryClass::SystemInfo => ENTRYCLASS_SYSTEM_INFO,
            EntryClass::Tombstone => ENTRYCLASS_TOMBSTONE,
            #[cfg(any(test, debug_assertions))]
            EntryClass::TestClass => TEST_ENTRYCLASS_TEST_CLASS,
            EntryClass::User => ENTRYCLASS_USER,
        }
    }
}

impl From<EntryClass> for JsonValue {
    fn from(value: EntryClass) -> Self {
        Self::String(value.as_ref().to_string())
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
        write!(f, "{s}")
    }
}

impl EntryClass {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_valueset(self) -> ValueSet {
        let s: &'static str = self.into();
        ValueSetIutf8::new(s)
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

// ============ TEST DATA ============
#[cfg(test)]
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};

#[cfg(test)]
lazy_static! {
    pub static ref E_TESTPERSON_1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("Test Person 1")),
        (
            Attribute::Uuid,
            Value::Uuid(super::uuids::UUID_TESTPERSON_1)
        )
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson2")),
        (Attribute::DisplayName, Value::new_utf8s("Test Person 2")),
        (
            Attribute::Uuid,
            Value::Uuid(super::uuids::UUID_TESTPERSON_2)
        )
    );
}
