//! Constant Entries for the IDM
use enum_iterator::Sequence;

use std::fmt::Display;

use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::value::PartialValue;
use crate::value::Value;
use kanidm_proto::constants::*;
use kanidm_proto::v1::{OperationError, UiHint};

#[cfg(test)]
use uuid::{uuid, Uuid};

#[test]
fn test_valueattribute_as_str() {
    assert!(ValueAttribute::Class.as_str() == "class");
}

#[test]
// this ensures we cover both ends of the conversion to/from string-types
fn test_valueattribute_round_trip() {
    use enum_iterator::all;
    let the_list = all::<ValueAttribute>().collect::<Vec<_>>();
    for attr in the_list {
        let s: &'static str = attr.into();
        let attr2 = ValueAttribute::try_from(s.to_string()).unwrap();
        assert!(attr == attr2);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Sequence)]
pub enum ValueAttribute {
    AcpCreateAttr,
    AcpCreateClass,
    AcpEnable,
    AcpModifyClass,
    AcpModifyPresentAttr,
    AcpModifyRemovedAttr,
    AcpReceiverGroup,
    AcpSearchAttr,
    AcpTargetScope,
    ApiTokenSession,
    Attr,
    AttributeName,
    BadlistPassword,
    Claim,
    Class,
    ClassName,
    Cn,
    CredentialUpdateIntentToken,
    Description,
    DeviceKeys,
    DirectMemberOf,
    DisplayName,
    DomainName,
    DomainUuid,
    DynMember,
    Email,
    EmailAlternative,
    EmailPrimary,
    GidNumber,
    GrantUiHint,
    IpaNtHash,
    JwsEs256PrivateKey,
    LastModifiedCid,
    LegalName,
    LoginShell,
    Member,
    MemberOf,
    MultiValue,
    Name,
    NameHistory,
    NoIndex,
    OAuth2AllowInsecureClientDisablePkce,
    OAuth2ConsentScopeMap,
    OAuth2JwtLegacyCryptoEnable,
    OAuth2PreferShortUsername,
    OAuth2RsBasicSecret,
    OAuth2RsName,
    OAuth2RsOrigin,
    OAuth2RsOriginLanding,
    OAuth2RsScopeMap,
    OAuth2RsSupScopeMap,
    OAuth2RsTokenKey,
    OAuth2Session,
    ObjectClass,
    OtherNoIndex,
    PassKeys,
    Phantom,
    PrimaryCredential,
    RadiusSecret,
    Replicated,
    SourceUuid,
    Spn,
    /// An LDAP-compatible sshpublickey
    SshPublicKey,
    /// The Kanidm-local ssh_publickey
    SshUnderscorePublicKey,
    SyncParentUuid,
    Syntax,
    SyncAllowed,
    Term,
    Uid,
    UidNumber,
    Unique,
    UnixPassword,
    UserAuthTokenSession,
    UserId,
    UserPassword,
    Uuid,
    Version,

    #[cfg(any(debug_assertions, test))]
    NonExist,
    #[cfg(any(debug_assertions, test))]
    TestAttr,
    #[cfg(any(debug_assertions, test))]
    Extra,
}

impl ValueAttribute {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl From<&ValueAttribute> for &'static str {
    fn from(value: &ValueAttribute) -> Self {
        (*value).into()
    }
}

impl TryFrom<String> for ValueAttribute {
    type Error = OperationError;
    fn try_from(val: String) -> Result<Self, OperationError> {
        let res = match val.as_str() {
            ATTR_ACP_CREATE_ATTR => ValueAttribute::AcpCreateAttr,
            ATTR_ACP_CREATE_CLASS => ValueAttribute::AcpCreateClass,
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE => {
                ValueAttribute::OAuth2AllowInsecureClientDisablePkce
            }
            ATTR_ACP_ENABLE => ValueAttribute::AcpEnable,
            ATTR_ACP_MODIFY_CLASS => ValueAttribute::AcpModifyClass,
            ATTR_ACP_MODIFY_PRESENTATTR => ValueAttribute::AcpModifyPresentAttr,
            ATTR_ACP_MODIFY_REMOVEDATTR => ValueAttribute::AcpModifyRemovedAttr,
            ATTR_ACP_RECEIVER_GROUP => ValueAttribute::AcpReceiverGroup,
            ATTR_ACP_SEARCH_ATTR => ValueAttribute::AcpSearchAttr,
            ATTR_ACP_TARGET_SCOPE => ValueAttribute::AcpTargetScope,
            ATTR_API_TOKEN_SESSION => ValueAttribute::ApiTokenSession,
            ATTR_ATTR => ValueAttribute::Attr,
            ATTR_ATTRIBUTENAME => ValueAttribute::AttributeName,
            ATTR_BADLIST_PASSWORD => ValueAttribute::BadlistPassword,
            ATTR_CLAIM => ValueAttribute::Claim,
            ATTR_CLASS => ValueAttribute::Class,
            ATTR_CLASSNAME => ValueAttribute::ClassName,
            ATTR_CN => ValueAttribute::Cn,
            ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN => ValueAttribute::CredentialUpdateIntentToken,
            ATTR_DESCRIPTION => ValueAttribute::Description,
            ATTR_DIRECTMEMBEROF => ValueAttribute::DirectMemberOf,
            ATTR_DISPLAYNAME => ValueAttribute::DisplayName,
            ATTR_DOMAIN_NAME => ValueAttribute::DomainName,
            ATTR_DOMAIN_UUID => ValueAttribute::DomainUuid,
            ATTR_DYNMEMBER => ValueAttribute::DynMember,
            ATTR_EMAIL => ValueAttribute::Email,
            ATTR_EMAIL_ALTERNATIVE => ValueAttribute::EmailAlternative,
            ATTR_EMAIL_PRIMARY => ValueAttribute::EmailPrimary,
            ATTR_GIDNUMBER => ValueAttribute::GidNumber,
            ATTR_GRANT_UI_HINT => ValueAttribute::GrantUiHint,
            ATTR_IPANTHASH => ValueAttribute::IpaNtHash,
            ATTR_JWS_ES256_PRIVATE_KEY => ValueAttribute::JwsEs256PrivateKey,
            ATTR_LAST_MODIFIED_CID => ValueAttribute::LastModifiedCid,
            ATTR_LOGINSHELL => ValueAttribute::LoginShell,
            ATTR_MEMBER => ValueAttribute::Member,
            ATTR_MEMBEROF => ValueAttribute::MemberOf,
            ATTR_MULTIVALUE => ValueAttribute::MultiValue,
            ATTR_NAME => ValueAttribute::Name,
            ATTR_NO_INDEX => ValueAttribute::NoIndex,
            ATTR_OAUTH2_CONSENT_SCOPE_MAP => ValueAttribute::OAuth2ConsentScopeMap,
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE => ValueAttribute::OAuth2JwtLegacyCryptoEnable,
            ATTR_OAUTH2_PREFER_SHORT_USERNAME => ValueAttribute::OAuth2PreferShortUsername,
            ATTR_OAUTH2_RS_BASIC_SECRET => ValueAttribute::OAuth2RsBasicSecret,
            ATTR_OAUTH2_RS_NAME => ValueAttribute::OAuth2RsName,
            ATTR_OAUTH2_RS_ORIGIN => ValueAttribute::OAuth2RsOrigin,
            ATTR_OAUTH2_RS_ORIGIN_LANDING => ValueAttribute::OAuth2RsOriginLanding,
            ATTR_OAUTH2_RS_SCOPE_MAP => ValueAttribute::OAuth2RsScopeMap,
            ATTR_OAUTH2_RS_SUP_SCOPE_MAP => ValueAttribute::OAuth2RsSupScopeMap,
            ATTR_OAUTH2_RS_TOKEN_KEY => ValueAttribute::OAuth2RsTokenKey,
            ATTR_OAUTH2_SESSION => ValueAttribute::OAuth2Session,
            ATTR_OBJECTCLASS => ValueAttribute::ObjectClass,
            ATTR_OTHER_NO_INDEX => ValueAttribute::OtherNoIndex,
            ATTR_PASSKEYS => ValueAttribute::PassKeys,
            ATTR_PHANTOM => ValueAttribute::Phantom,
            ATTR_PRIMARY_CREDENTIAL => ValueAttribute::PrimaryCredential,
            ATTR_REPLICATED => ValueAttribute::Replicated,
            ATTR_SOURCE_UUID => ValueAttribute::SourceUuid,
            ATTR_SPN => ValueAttribute::Spn,
            ATTR_SSHPUBLICKEY => ValueAttribute::SshPublicKey,
            ATTR_SSH_PUBLICKEY => ValueAttribute::SshUnderscorePublicKey,
            ATTR_SYNC_ALLOWED => ValueAttribute::SyncAllowed,
            ATTR_SYNC_PARENT_UUID => ValueAttribute::SyncParentUuid,
            ATTR_SYNTAX => ValueAttribute::Syntax,
            ATTR_TERM => ValueAttribute::Term,
            ATTR_UID => ValueAttribute::Uid,
            ATTR_UIDNUMBER => ValueAttribute::UidNumber,
            ATTR_UNIQUE => ValueAttribute::Unique,
            ATTR_UNIXPASSWORD => ValueAttribute::UnixPassword,
            ATTR_USER_AUTH_TOKEN_SESSION => ValueAttribute::UserAuthTokenSession,
            ATTR_USERID => ValueAttribute::UserId,
            ATTR_USERPASSWORD => ValueAttribute::UserPassword,
            ATTR_UUID => ValueAttribute::Uuid,
            ATTR_VERSION => ValueAttribute::Version,
            ATTR_NAME_HISTORY => ValueAttribute::NameHistory,
            ATTR_DEVICEKEYS => ValueAttribute::DeviceKeys,
            ATTR_LEGALNAME => ValueAttribute::LegalName,
            ATTR_RADIUS_SECRET => ValueAttribute::RadiusSecret,

            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NON_EXIST => ValueAttribute::NonExist,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_TEST_ATTR => ValueAttribute::TestAttr,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_EXTRA => ValueAttribute::Extra,
            _ => return Err(OperationError::InvalidAttributeName(val)),
        };
        Ok(res)
    }
}

impl From<ValueAttribute> for &'static str {
    fn from(val: ValueAttribute) -> Self {
        match val {
            ValueAttribute::DeviceKeys => ATTR_DEVICEKEYS,
            ValueAttribute::LegalName => ATTR_LEGALNAME,
            ValueAttribute::UnixPassword => ATTR_UNIXPASSWORD,
            ValueAttribute::RadiusSecret => ATTR_RADIUS_SECRET,
            ValueAttribute::NameHistory => ATTR_NAME_HISTORY,

            ValueAttribute::AcpCreateAttr => ATTR_ACP_CREATE_ATTR,
            ValueAttribute::AcpCreateClass => ATTR_ACP_CREATE_CLASS,
            ValueAttribute::AcpEnable => ATTR_ACP_ENABLE,
            ValueAttribute::AcpModifyClass => ATTR_ACP_MODIFY_CLASS,
            ValueAttribute::AcpModifyPresentAttr => ATTR_ACP_MODIFY_PRESENTATTR,
            ValueAttribute::AcpModifyRemovedAttr => ATTR_ACP_MODIFY_REMOVEDATTR,
            ValueAttribute::AcpReceiverGroup => ATTR_ACP_RECEIVER_GROUP,
            ValueAttribute::AcpSearchAttr => ATTR_ACP_SEARCH_ATTR,
            ValueAttribute::AcpTargetScope => ATTR_ACP_TARGET_SCOPE,
            ValueAttribute::ApiTokenSession => ATTR_API_TOKEN_SESSION,
            ValueAttribute::Attr => ATTR_ATTR,
            ValueAttribute::AttributeName => ATTR_ATTRIBUTENAME,
            ValueAttribute::BadlistPassword => ATTR_BADLIST_PASSWORD,
            ValueAttribute::Claim => ATTR_CLAIM,
            ValueAttribute::Class => ATTR_CLASS,
            ValueAttribute::ClassName => ATTR_CLASSNAME,
            ValueAttribute::Cn => ATTR_CN,
            ValueAttribute::CredentialUpdateIntentToken => ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
            ValueAttribute::Description => ATTR_DESCRIPTION,
            ValueAttribute::DirectMemberOf => ATTR_DIRECTMEMBEROF,
            ValueAttribute::DisplayName => ATTR_DISPLAYNAME,
            ValueAttribute::DomainName => ATTR_DOMAIN_NAME,
            ValueAttribute::DomainUuid => ATTR_DOMAIN_UUID,
            ValueAttribute::DynMember => ATTR_DYNMEMBER,
            ValueAttribute::Email => ATTR_EMAIL,
            ValueAttribute::EmailAlternative => ATTR_EMAIL_ALTERNATIVE,
            ValueAttribute::EmailPrimary => ATTR_EMAIL_PRIMARY,
            ValueAttribute::GidNumber => ATTR_GIDNUMBER,
            ValueAttribute::GrantUiHint => ATTR_GRANT_UI_HINT,
            ValueAttribute::IpaNtHash => ATTR_IPANTHASH,
            ValueAttribute::JwsEs256PrivateKey => ATTR_JWS_ES256_PRIVATE_KEY,
            ValueAttribute::LastModifiedCid => ATTR_LAST_MODIFIED_CID,
            ValueAttribute::LoginShell => ATTR_LOGINSHELL,
            ValueAttribute::Member => ATTR_MEMBER,
            ValueAttribute::MemberOf => ATTR_MEMBEROF,
            ValueAttribute::MultiValue => ATTR_MULTIVALUE,
            ValueAttribute::Name => ATTR_NAME,
            ValueAttribute::NoIndex => ATTR_NO_INDEX,
            ValueAttribute::OAuth2AllowInsecureClientDisablePkce => {
                ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
            }
            ValueAttribute::OAuth2ConsentScopeMap => ATTR_OAUTH2_CONSENT_SCOPE_MAP,
            ValueAttribute::OAuth2JwtLegacyCryptoEnable => ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
            ValueAttribute::OAuth2PreferShortUsername => ATTR_OAUTH2_PREFER_SHORT_USERNAME,
            ValueAttribute::OAuth2RsBasicSecret => ATTR_OAUTH2_RS_BASIC_SECRET,
            ValueAttribute::OAuth2RsName => ATTR_OAUTH2_RS_NAME,
            ValueAttribute::OAuth2RsOrigin => ATTR_OAUTH2_RS_ORIGIN,
            ValueAttribute::OAuth2RsOriginLanding => ATTR_OAUTH2_RS_ORIGIN_LANDING,
            ValueAttribute::OAuth2RsScopeMap => ATTR_OAUTH2_RS_SCOPE_MAP,
            ValueAttribute::OAuth2RsSupScopeMap => ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
            ValueAttribute::OAuth2RsTokenKey => ATTR_OAUTH2_RS_TOKEN_KEY,
            ValueAttribute::OAuth2Session => ATTR_OAUTH2_SESSION,
            ValueAttribute::ObjectClass => ATTR_OBJECTCLASS,
            ValueAttribute::OtherNoIndex => ATTR_OTHER_NO_INDEX,
            ValueAttribute::PassKeys => ATTR_PASSKEYS,
            ValueAttribute::Phantom => ATTR_PHANTOM,
            ValueAttribute::PrimaryCredential => ATTR_PRIMARY_CREDENTIAL,
            ValueAttribute::Replicated => ATTR_REPLICATED,
            ValueAttribute::SourceUuid => ATTR_SOURCE_UUID,
            ValueAttribute::Spn => ATTR_SPN,
            ValueAttribute::SshPublicKey => ATTR_SSHPUBLICKEY,
            ValueAttribute::SshUnderscorePublicKey => ATTR_SSH_PUBLICKEY,
            ValueAttribute::SyncAllowed => ATTR_SYNC_ALLOWED,
            ValueAttribute::SyncParentUuid => ATTR_SYNC_PARENT_UUID,
            ValueAttribute::Syntax => ATTR_SYNTAX,
            ValueAttribute::Term => ATTR_TERM,
            ValueAttribute::Uid => ATTR_UID,
            ValueAttribute::UidNumber => ATTR_UIDNUMBER,
            ValueAttribute::Unique => ATTR_UNIQUE,
            ValueAttribute::UserAuthTokenSession => ATTR_USER_AUTH_TOKEN_SESSION,
            ValueAttribute::UserId => ATTR_USERID,
            ValueAttribute::UserPassword => ATTR_USERPASSWORD,
            ValueAttribute::Uuid => ATTR_UUID,
            ValueAttribute::Version => ATTR_VERSION,

            #[cfg(any(debug_assertions, test))]
            ValueAttribute::NonExist => TEST_ATTR_NON_EXIST,
            #[cfg(any(debug_assertions, test))]
            ValueAttribute::TestAttr => TEST_ATTR_TEST_ATTR,
            #[cfg(any(debug_assertions, test))]
            ValueAttribute::Extra => TEST_ATTR_EXTRA,
        }
    }
}

impl From<ValueAttribute> for crate::prelude::AttrString {
    fn from(val: ValueAttribute) -> Self {
        crate::prelude::AttrString::from(val.to_string())
    }
}

impl Display for ValueAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}

impl ValueAttribute {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_partialvalue(self) -> PartialValue {
        let s: &'static str = self.into();
        PartialValue::new_iutf8(s)
    }
}

#[derive(Copy, Clone)]
pub enum ValueClass {
    AccessControlCreate,
    AccessControlDelete,
    AccessControlModify,
    AccessControlProfile,
    AccessControlSearch,
    Account,
    AttributeType,
    Class,
    ClassType,
    Conflict,
    DomainInfo,
    DynGroup,
    ExtensibleObject,
    Group,
    MemberOf,
    OAuth2ResourceServer,
    OAuth2ResourceServerBasic,
    OAuth2ResourceServerPublic,
    Object,
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
    SourceUuid,
    #[cfg(any(test, debug_assertions))]
    TestClass,
}

impl From<ValueClass> for &'static str {
    fn from(val: ValueClass) -> Self {
        match val {
            ValueClass::AccessControlCreate => "access_control_create",
            ValueClass::AccessControlDelete => "access_control_delete",
            ValueClass::AccessControlModify => "access_control_modify",
            ValueClass::AccessControlProfile => "access_control_profile",
            ValueClass::AccessControlSearch => "access_control_search",
            ValueClass::Account => "account",
            ValueClass::AttributeType => "attributetype",
            ValueClass::Class => "class",
            ValueClass::ClassType => "classtype",
            ValueClass::Conflict => "conflict",
            ValueClass::DomainInfo => "domain_info",
            ValueClass::DynGroup => "dyngroup",
            ValueClass::ExtensibleObject => "extensibleobject",
            ValueClass::Group => "group",
            ValueClass::MemberOf => "memberof",
            ValueClass::OAuth2ResourceServer => "oauth2_resource_server",
            ValueClass::OAuth2ResourceServerBasic => "oauth2_resource_server_basic",
            ValueClass::OAuth2ResourceServerPublic => "oauth2_resource_server_public",
            ValueClass::Object => "object",
            ValueClass::Person => "person",
            ValueClass::PosixAccount => "posixaccount",
            ValueClass::PosixGroup => "posixgroup",
            ValueClass::Recycled => "recycled",
            ValueClass::Service => "service",
            ValueClass::ServiceAccount => "service_account",
            ValueClass::SourceUuid => CLASS_SOURCEUUID,
            ValueClass::SyncAccount => "sync_account",
            ValueClass::SyncObject => "sync_object",
            ValueClass::System => "system",
            ValueClass::SystemConfig => "system_config",
            ValueClass::SystemInfo => "system_info",
            ValueClass::Tombstone => "tombstone",
            #[cfg(any(test, debug_assertions))]
            ValueClass::TestClass => "testclass",
            ValueClass::User => "user",
        }
    }
}

impl From<ValueClass> for String {
    fn from(val: ValueClass) -> Self {
        let s: &'static str = val.into();
        s.to_string()
    }
}

impl From<ValueClass> for Value {
    fn from(val: ValueClass) -> Self {
        Value::new_iutf8(val.into())
    }
}

impl From<ValueClass> for PartialValue {
    fn from(val: ValueClass) -> Self {
        PartialValue::new_iutf8(val.into())
    }
}

impl From<ValueClass> for crate::prelude::AttrString {
    fn from(val: ValueClass) -> Self {
        crate::prelude::AttrString::from(val.to_string())
    }
}

impl Display for ValueClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = (*self).into();
        write!(f, "{}", s)
    }
}

impl ValueClass {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_partialvalue(self) -> PartialValue {
        let s: &'static str = self.into();
        PartialValue::new_iutf8(s)
    }
}

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
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Account.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::MemberOf.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Object.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::ServiceAccount.to_value()
        ),
        (ValueAttribute::Name.as_str(), Value::new_iname("admin")),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_ADMIN)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin System Admin account.")
        ),
        (
            ValueAttribute::DisplayName.as_str(),
            Value::new_utf8s("System Administrator")
        )
    );
}

lazy_static! {
    /// Builtin IDM Admin account.
    pub static ref E_IDM_ADMIN_V1: EntryInitNew = entry_init!(
        (ValueAttribute::Class.as_str(), ValueClass::Account.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::MemberOf.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::Object.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::ServiceAccount.to_value()),
        (ValueAttribute::Name.as_str(), Value::new_iname("idm_admin")),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_IDM_ADMIN)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Admin account.")
        ),
        (ValueAttribute::DisplayName.as_str(), Value::new_utf8s("IDM Administrator"))
    );
}

lazy_static! {
    /// Builtin IDM Administrators Group.
    pub static ref E_IDM_ADMINS_V1: EntryInitNew = entry_init!(
        (ValueAttribute::Class.as_str(), ValueClass::Group.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::Object.to_value()),
        (ValueAttribute::Name.as_str(), Value::new_iname("idm_admins")),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_IDM_ADMINS)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Administrators Group.")
        ),
        (ValueAttribute::Member.as_str(), Value::Refer(UUID_IDM_ADMIN))
    );
}

lazy_static! {
    /// Builtin System Administrators Group.
    pub static ref E_SYSTEM_ADMINS_V1: EntryInitNew = entry_init!(
        (ValueAttribute::Class.as_str(), ValueClass::Group.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::Object.to_value()),
        (ValueAttribute::Name.as_str(), Value::new_iname("system_admins")),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_SYSTEM_ADMINS)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Builtin System Administrators Group.")
        ),
        (ValueAttribute::Member.as_str(), Value::Refer(UUID_ADMIN))
    );
}

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
        "description": ["Builtin IDM Group for managing synchronisation from external identity sources"],
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
        (ValueAttribute::Class.as_str(), ValueClass::Object.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::Group.to_value()),
        (
            ValueAttribute::Name.as_str(),
            Value::new_iname("idm_ui_enable_experimental_features")
        ),
        (
            ValueAttribute::Uuid.as_str(),
            Value::Uuid(UUID_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES)
        ),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s(
                "Members of this group will have access to experimental web UI features."
            )
        ),
        (ValueAttribute::GrantUiHint .as_str(), Value::UiHint(UiHint::ExperimentalFeatures))
    );

    pub static ref E_IDM_ACCOUNT_MAIL_READ_PRIV: EntryInitNew = entry_init!(
        (ValueAttribute::Class.as_str(), ValueClass::Object.to_value()),
        (ValueAttribute::Class.as_str(), ValueClass::Group.to_value()),
        (
            ValueAttribute::Name.as_str(),
            Value::new_iname("idm_account_mail_read_priv")
        ),
        (
            ValueAttribute::Uuid.as_str(),
            Value::Uuid(UUID_IDM_ACCOUNT_MAIL_READ_PRIV)
        ),
        (
            ValueAttribute::Description.as_str(),
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

lazy_static! {
    pub static ref E_SYSTEM_INFO_V1: EntryInitNew = entry_init!(
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Object.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::SystemInfo.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::System.to_value()
        ),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_SYSTEM_INFO)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("System (local) info and metadata object.")
        ),
        (ValueAttribute::Version.as_str(), Value::Uint32(14))
    );
}

lazy_static! {
    pub static ref E_DOMAIN_INFO_V1: EntryInitNew = entry_init!(
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Object.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::DomainInfo.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::System.to_value()
        ),
        (
            ValueAttribute::Name.as_str(),
            Value::new_iname("domain_local")
        ),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_DOMAIN_INFO)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("This local domain's info and metadata object.")
        )
    );
}

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
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Object.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Account.to_value()
        ),
        (
            ValueAttribute::Class.as_str(),
            ValueClass::ServiceAccount.to_value()
        ),
        (ValueAttribute::Name.as_str(), Value::new_iname("anonymous")),
        (ValueAttribute::Uuid.as_str(), Value::Uuid(UUID_ANONYMOUS)),
        (
            ValueAttribute::Description.as_str(),
            Value::new_utf8s("Anonymous access account.")
        ),
        (
            ValueAttribute::DisplayName.as_str(),
            Value::new_utf8s("Anonymous")
        )
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
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Object.to_value()
        ),
        (
            ValueAttribute::Name.as_str(),
            Value::new_iname("testperson1")
        ),
        (
            ValueAttribute::Uuid.as_str(),
            Value::Uuid(UUID_TESTPERSON_1)
        )
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        (
            ValueAttribute::Class.as_str(),
            ValueClass::Object.to_value()
        ),
        (
            ValueAttribute::Name.as_str(),
            Value::new_iname("testperson2")
        ),
        (
            ValueAttribute::Uuid.as_str(),
            Value::Uuid(UUID_TESTPERSON_2)
        )
    );
}
