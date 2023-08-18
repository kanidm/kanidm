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
    assert!(Attribute::Class.as_str() == "class");
    assert!(Attribute::Class.to_string() == String::from("class"));
}

#[test]
// this ensures we cover both ends of the conversion to/from string-types
fn test_valueattribute_round_trip() {
    use enum_iterator::all;
    let the_list = all::<Attribute>().collect::<Vec<_>>();
    for attr in the_list {
        let s: &'static str = attr.into();
        let attr2 = Attribute::try_from(s.to_string()).unwrap();
        assert!(attr == attr2);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Sequence)]
pub enum Attribute {
    Account,
    AccountExpire,
    AccountValidFrom,
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
    CookiePrivateKey,
    CredentialUpdateIntentToken,
    Description,
    DeviceKeys,
    DirectMemberOf,
    DisplayName,
    DomainDisplayName,
    DomainLdapBasedn,
    DomainName,
    DomainSsid,
    DomainTokenKey,
    DomainUuid,
    DynGroup,
    DynGroupFilter,
    DynMember,
    Email,
    EmailAlternative,
    EmailPrimary,
    Es256PrivateKeyDer,
    FernetPrivateKeyStr,
    GidNumber,
    GrantUiHint,
    Group,
    IdVerificationEcKey,
    Index,
    IpaNtHash,
    JwsEs256PrivateKey,
    LastModifiedCid,
    LegalName,
    LoginShell,
    Mail,
    May,
    Member,
    MemberOf,
    MultiValue,
    Must,
    Name,
    NameHistory,
    NoIndex,
    NsUniqueId,
    OAuth2AllowInsecureClientDisablePkce,
    OAuth2ConsentScopeMap,
    OAuth2JwtLegacyCryptoEnable,
    OAuth2PreferShortUsername,
    OAuth2RsBasicSecret,
    OAuth2RsImplicitScopes,
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
    PasswordImport,
    Phantom,
    PrimaryCredential,
    PrivateCookieKey,
    RadiusSecret,
    Replicated,
    Rs256PrivateKeyDer,
    SourceUuid,
    Spn,
    SshPublicKey,
    /// An LDAP-compatible sshpublickey
    SshUnderscorePublicKey,
    /// The Kanidm-local ssh_publickey
    SyncAllowed,
    SyncCookie,
    SyncCredentialPortal,
    SyncParentUuid,
    SyncTokenSession,
    SyncYieldAuthority,
    Syntax,
    SystemMay,
    SystemMust,
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

impl Attribute {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl From<&Attribute> for &'static str {
    fn from(value: &Attribute) -> Self {
        (*value).into()
    }
}

impl TryFrom<String> for Attribute {
    type Error = OperationError;
    fn try_from(val: String) -> Result<Self, OperationError> {
        let res = match val.as_str() {
            ATTR_ACCOUNT => Attribute::Account,
            ATTR_ACCOUNT_EXPIRE => Attribute::AccountExpire,
            ATTR_ACCOUNT_VALID_FROM => Attribute::AccountValidFrom,
            ATTR_ACP_CREATE_ATTR => Attribute::AcpCreateAttr,
            ATTR_ACP_CREATE_CLASS => Attribute::AcpCreateClass,
            ATTR_ACP_ENABLE => Attribute::AcpEnable,
            ATTR_ACP_MODIFY_CLASS => Attribute::AcpModifyClass,
            ATTR_ACP_MODIFY_PRESENTATTR => Attribute::AcpModifyPresentAttr,
            ATTR_ACP_MODIFY_REMOVEDATTR => Attribute::AcpModifyRemovedAttr,
            ATTR_ACP_RECEIVER_GROUP => Attribute::AcpReceiverGroup,
            ATTR_ACP_SEARCH_ATTR => Attribute::AcpSearchAttr,
            ATTR_ACP_TARGET_SCOPE => Attribute::AcpTargetScope,
            ATTR_API_TOKEN_SESSION => Attribute::ApiTokenSession,
            ATTR_ATTR => Attribute::Attr,
            ATTR_ATTRIBUTENAME => Attribute::AttributeName,
            ATTR_BADLIST_PASSWORD => Attribute::BadlistPassword,
            ATTR_CLAIM => Attribute::Claim,
            ATTR_CLASS => Attribute::Class,
            ATTR_CLASSNAME => Attribute::ClassName,
            ATTR_CN => Attribute::Cn,
            ATTR_COOKIE_PRIVATE_KEY => Attribute::CookiePrivateKey,
            ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN => Attribute::CredentialUpdateIntentToken,
            ATTR_DESCRIPTION => Attribute::Description,
            ATTR_DEVICEKEYS => Attribute::DeviceKeys,
            ATTR_DIRECTMEMBEROF => Attribute::DirectMemberOf,
            ATTR_DISPLAYNAME => Attribute::DisplayName,
            ATTR_DOMAIN_DISPLAY_NAME => Attribute::DomainDisplayName,
            ATTR_DOMAIN_LDAP_BASEDN => Attribute::DomainLdapBasedn,
            ATTR_DOMAIN_NAME => Attribute::DomainName,
            ATTR_DOMAIN_SSID => Attribute::DomainSsid,
            ATTR_DOMAIN_TOKEN_KEY => Attribute::DomainTokenKey,
            ATTR_DOMAIN_UUID => Attribute::DomainUuid,
            ATTR_DYNGROUP => Attribute::DynGroup,
            ATTR_DYNGROUP_FILTER => Attribute::DynGroupFilter,
            ATTR_DYNMEMBER => Attribute::DynMember,
            ATTR_EMAIL => Attribute::Email,
            ATTR_EMAIL_ALTERNATIVE => Attribute::EmailAlternative,
            ATTR_EMAIL_PRIMARY => Attribute::EmailPrimary,
            ATTR_ES256_PRIVATE_KEY_DER => Attribute::Es256PrivateKeyDer,
            ATTR_FERNET_PRIVATE_KEY_STR => Attribute::FernetPrivateKeyStr,
            ATTR_GROUP => Attribute::Group,
            ATTR_GIDNUMBER => Attribute::GidNumber,
            ATTR_GRANT_UI_HINT => Attribute::GrantUiHint,
            ATTR_ID_VERIFICATION_ECKEY => Attribute::IdVerificationEcKey,
            ATTR_INDEX => Attribute::Index,
            ATTR_IPANTHASH => Attribute::IpaNtHash,
            ATTR_JWS_ES256_PRIVATE_KEY => Attribute::JwsEs256PrivateKey,
            ATTR_LAST_MODIFIED_CID => Attribute::LastModifiedCid,
            ATTR_LEGALNAME => Attribute::LegalName,
            ATTR_LOGINSHELL => Attribute::LoginShell,
            ATTR_MAIL => Attribute::Mail,
            ATTR_MAY => Attribute::May,
            ATTR_MEMBER => Attribute::Member,
            ATTR_MEMBEROF => Attribute::MemberOf,
            ATTR_MULTIVALUE => Attribute::MultiValue,
            ATTR_MUST => Attribute::Must,
            ATTR_NAME => Attribute::Name,
            ATTR_NAME_HISTORY => Attribute::NameHistory,
            ATTR_NO_INDEX => Attribute::NoIndex,
            ATTR_NSUNIQUEID => Attribute::NsUniqueId,
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE => {
                Attribute::OAuth2AllowInsecureClientDisablePkce
            }
            ATTR_OAUTH2_CONSENT_SCOPE_MAP => Attribute::OAuth2ConsentScopeMap,
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE => Attribute::OAuth2JwtLegacyCryptoEnable,
            ATTR_OAUTH2_PREFER_SHORT_USERNAME => Attribute::OAuth2PreferShortUsername,
            ATTR_OAUTH2_RS_BASIC_SECRET => Attribute::OAuth2RsBasicSecret,
            ATTR_OAUTH2_RS_IMPLICIT_SCOPES => Attribute::OAuth2RsImplicitScopes,
            ATTR_OAUTH2_RS_NAME => Attribute::OAuth2RsName,
            ATTR_OAUTH2_RS_ORIGIN => Attribute::OAuth2RsOrigin,
            ATTR_OAUTH2_RS_ORIGIN_LANDING => Attribute::OAuth2RsOriginLanding,
            ATTR_OAUTH2_RS_SCOPE_MAP => Attribute::OAuth2RsScopeMap,
            ATTR_OAUTH2_RS_SUP_SCOPE_MAP => Attribute::OAuth2RsSupScopeMap,
            ATTR_OAUTH2_RS_TOKEN_KEY => Attribute::OAuth2RsTokenKey,
            ATTR_OAUTH2_SESSION => Attribute::OAuth2Session,
            ATTR_OBJECTCLASS => Attribute::ObjectClass,
            ATTR_OTHER_NO_INDEX => Attribute::OtherNoIndex,
            ATTR_PASSKEYS => Attribute::PassKeys,
            ATTR_PASSWORD_IMPORT => Attribute::PasswordImport,
            ATTR_PHANTOM => Attribute::Phantom,
            ATTR_PRIMARY_CREDENTIAL => Attribute::PrimaryCredential,
            ATTR_PRIVATE_COOKIE_KEY => Attribute::PrivateCookieKey,
            ATTR_RADIUS_SECRET => Attribute::RadiusSecret,
            ATTR_REPLICATED => Attribute::Replicated,
            ATTR_RS256_PRIVATE_KEY_DER => Attribute::Rs256PrivateKeyDer,
            ATTR_SOURCE_UUID => Attribute::SourceUuid,
            ATTR_SPN => Attribute::Spn,
            ATTR_SSH_PUBLICKEY => Attribute::SshUnderscorePublicKey,
            ATTR_SSHPUBLICKEY => Attribute::SshPublicKey,
            ATTR_SYNC_ALLOWED => Attribute::SyncAllowed,
            ATTR_SYNC_COOKIE => Attribute::SyncCookie,
            ATTR_SYNC_CREDENTIAL_PORTAL => Attribute::SyncCredentialPortal,
            ATTR_SYNC_PARENT_UUID => Attribute::SyncParentUuid,
            ATTR_SYNC_TOKEN_SESSION => Attribute::SyncTokenSession,
            ATTR_SYNC_YIELD_AUTHORITY => Attribute::SyncYieldAuthority,
            ATTR_SYNTAX => Attribute::Syntax,
            ATTR_SYSTEMMAY => Attribute::SystemMay,
            ATTR_SYSTEMMUST => Attribute::SystemMust,
            ATTR_TERM => Attribute::Term,
            ATTR_UID => Attribute::Uid,
            ATTR_UIDNUMBER => Attribute::UidNumber,
            ATTR_UNIQUE => Attribute::Unique,
            ATTR_UNIX_PASSWORD => Attribute::UnixPassword,
            ATTR_USER_AUTH_TOKEN_SESSION => Attribute::UserAuthTokenSession,
            ATTR_USERID => Attribute::UserId,
            ATTR_USERPASSWORD => Attribute::UserPassword,
            ATTR_UUID => Attribute::Uuid,
            ATTR_VERSION => Attribute::Version,

            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NON_EXIST => Attribute::NonExist,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_TEST_ATTR => Attribute::TestAttr,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_EXTRA => Attribute::Extra,
            _ => return Err(OperationError::InvalidAttributeName(val)),
        };
        Ok(res)
    }
}

impl From<Attribute> for &'static str {
    fn from(val: Attribute) -> Self {
        match val {
            Attribute::Account => ATTR_ACCOUNT,
            Attribute::SystemMay => ATTR_SYSTEMMAY,
            Attribute::DynGroup => ATTR_DYNGROUP,
            Attribute::May => ATTR_MAY,
            Attribute::DomainDisplayName => ATTR_DOMAIN_DISPLAY_NAME,
            Attribute::SyncCredentialPortal => ATTR_SYNC_CREDENTIAL_PORTAL,
            Attribute::SyncCookie => ATTR_SYNC_COOKIE,
            Attribute::SyncYieldAuthority => ATTR_SYNC_YIELD_AUTHORITY,
            Attribute::SyncTokenSession => ATTR_SYNC_TOKEN_SESSION,
            Attribute::Es256PrivateKeyDer => ATTR_ES256_PRIVATE_KEY_DER,
            Attribute::Rs256PrivateKeyDer => ATTR_RS256_PRIVATE_KEY_DER,
            Attribute::SystemMust => ATTR_SYSTEMMUST,
            Attribute::AccountExpire => ATTR_ACCOUNT_EXPIRE,
            Attribute::AccountValidFrom => ATTR_ACCOUNT_VALID_FROM,
            Attribute::LegalName => ATTR_LEGALNAME,
            Attribute::DeviceKeys => ATTR_DEVICEKEYS,
            Attribute::DynGroupFilter => ATTR_DYNGROUP_FILTER,
            Attribute::UnixPassword => ATTR_UNIX_PASSWORD,
            Attribute::RadiusSecret => ATTR_RADIUS_SECRET,
            Attribute::NameHistory => ATTR_NAME_HISTORY,
            Attribute::Must => ATTR_MUST,
            Attribute::AcpCreateAttr => ATTR_ACP_CREATE_ATTR,
            Attribute::AcpCreateClass => ATTR_ACP_CREATE_CLASS,
            Attribute::AcpEnable => ATTR_ACP_ENABLE,
            Attribute::AcpModifyClass => ATTR_ACP_MODIFY_CLASS,
            Attribute::AcpModifyPresentAttr => ATTR_ACP_MODIFY_PRESENTATTR,
            Attribute::AcpModifyRemovedAttr => ATTR_ACP_MODIFY_REMOVEDATTR,
            Attribute::AcpReceiverGroup => ATTR_ACP_RECEIVER_GROUP,
            Attribute::AcpSearchAttr => ATTR_ACP_SEARCH_ATTR,
            Attribute::AcpTargetScope => ATTR_ACP_TARGET_SCOPE,
            Attribute::ApiTokenSession => ATTR_API_TOKEN_SESSION,
            Attribute::Attr => ATTR_ATTR,
            Attribute::Group => ATTR_GROUP,
            Attribute::DomainLdapBasedn => ATTR_DOMAIN_LDAP_BASEDN,
            Attribute::FernetPrivateKeyStr => ATTR_FERNET_PRIVATE_KEY_STR,
            Attribute::CookiePrivateKey => ATTR_COOKIE_PRIVATE_KEY,

            Attribute::NsUniqueId => ATTR_NSUNIQUEID,
            Attribute::IdVerificationEcKey => ATTR_ID_VERIFICATION_ECKEY,

            Attribute::DomainSsid => ATTR_DOMAIN_SSID,
            Attribute::AttributeName => ATTR_ATTRIBUTENAME,
            Attribute::BadlistPassword => ATTR_BADLIST_PASSWORD,
            Attribute::Claim => ATTR_CLAIM,
            Attribute::Class => ATTR_CLASS,
            Attribute::ClassName => ATTR_CLASSNAME,
            Attribute::Cn => ATTR_CN,
            Attribute::CredentialUpdateIntentToken => ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
            Attribute::Description => ATTR_DESCRIPTION,
            Attribute::DirectMemberOf => ATTR_DIRECTMEMBEROF,
            Attribute::DisplayName => ATTR_DISPLAYNAME,
            Attribute::DomainName => ATTR_DOMAIN_NAME,
            Attribute::DomainUuid => ATTR_DOMAIN_UUID,
            Attribute::DomainTokenKey => ATTR_DOMAIN_TOKEN_KEY,
            Attribute::DynMember => ATTR_DYNMEMBER,
            Attribute::Email => ATTR_EMAIL,
            Attribute::EmailAlternative => ATTR_EMAIL_ALTERNATIVE,
            Attribute::EmailPrimary => ATTR_EMAIL_PRIMARY,
            Attribute::GidNumber => ATTR_GIDNUMBER,
            Attribute::GrantUiHint => ATTR_GRANT_UI_HINT,
            Attribute::Index => ATTR_INDEX,
            Attribute::IpaNtHash => ATTR_IPANTHASH,
            Attribute::JwsEs256PrivateKey => ATTR_JWS_ES256_PRIVATE_KEY,
            Attribute::LastModifiedCid => ATTR_LAST_MODIFIED_CID,
            Attribute::LoginShell => ATTR_LOGINSHELL,
            Attribute::Mail => ATTR_MAIL,
            Attribute::Member => ATTR_MEMBER,
            Attribute::MemberOf => ATTR_MEMBEROF,
            Attribute::MultiValue => ATTR_MULTIVALUE,
            Attribute::Name => ATTR_NAME,
            Attribute::NoIndex => ATTR_NO_INDEX,
            Attribute::OAuth2AllowInsecureClientDisablePkce => {
                ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
            }
            Attribute::OAuth2ConsentScopeMap => ATTR_OAUTH2_CONSENT_SCOPE_MAP,
            Attribute::OAuth2JwtLegacyCryptoEnable => ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
            Attribute::OAuth2PreferShortUsername => ATTR_OAUTH2_PREFER_SHORT_USERNAME,
            Attribute::OAuth2RsBasicSecret => ATTR_OAUTH2_RS_BASIC_SECRET,
            Attribute::OAuth2RsImplicitScopes => ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
            Attribute::OAuth2RsName => ATTR_OAUTH2_RS_NAME,
            Attribute::OAuth2RsOrigin => ATTR_OAUTH2_RS_ORIGIN,
            Attribute::OAuth2RsOriginLanding => ATTR_OAUTH2_RS_ORIGIN_LANDING,
            Attribute::OAuth2RsScopeMap => ATTR_OAUTH2_RS_SCOPE_MAP,
            Attribute::OAuth2RsSupScopeMap => ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
            Attribute::OAuth2RsTokenKey => ATTR_OAUTH2_RS_TOKEN_KEY,
            Attribute::OAuth2Session => ATTR_OAUTH2_SESSION,
            Attribute::ObjectClass => ATTR_OBJECTCLASS,
            Attribute::OtherNoIndex => ATTR_OTHER_NO_INDEX,
            Attribute::PassKeys => ATTR_PASSKEYS,

            Attribute::PasswordImport => ATTR_PASSWORD_IMPORT,
            Attribute::Phantom => ATTR_PHANTOM,
            Attribute::PrimaryCredential => ATTR_PRIMARY_CREDENTIAL,
            Attribute::PrivateCookieKey => ATTR_PRIVATE_COOKIE_KEY,
            Attribute::Replicated => ATTR_REPLICATED,
            Attribute::SourceUuid => ATTR_SOURCE_UUID,
            Attribute::Spn => ATTR_SPN,
            Attribute::SshPublicKey => ATTR_SSHPUBLICKEY,
            Attribute::SshUnderscorePublicKey => ATTR_SSH_PUBLICKEY,
            Attribute::SyncAllowed => ATTR_SYNC_ALLOWED,
            Attribute::SyncParentUuid => ATTR_SYNC_PARENT_UUID,
            Attribute::Syntax => ATTR_SYNTAX,
            Attribute::Term => ATTR_TERM,
            Attribute::Uid => ATTR_UID,
            Attribute::UidNumber => ATTR_UIDNUMBER,
            Attribute::Unique => ATTR_UNIQUE,
            Attribute::UserAuthTokenSession => ATTR_USER_AUTH_TOKEN_SESSION,
            Attribute::UserId => ATTR_USERID,
            Attribute::UserPassword => ATTR_USERPASSWORD,
            Attribute::Uuid => ATTR_UUID,
            Attribute::Version => ATTR_VERSION,

            #[cfg(any(debug_assertions, test))]
            Attribute::NonExist => TEST_ATTR_NON_EXIST,
            #[cfg(any(debug_assertions, test))]
            Attribute::TestAttr => TEST_ATTR_TEST_ATTR,
            #[cfg(any(debug_assertions, test))]
            Attribute::Extra => TEST_ATTR_EXTRA,
        }
    }
}

impl From<Attribute> for crate::prelude::AttrString {
    fn from(val: Attribute) -> Self {
        crate::prelude::AttrString::from(val.to_string())
    }
}

impl Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}

impl Attribute {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_partialvalue(self) -> PartialValue {
        let s: &'static str = self.into();
        PartialValue::new_iutf8(s)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum EntryClass {
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
    SourceUuid,
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
            EntryClass::AccessControlSearch => "access_control_search",
            EntryClass::Account => "account",
            EntryClass::AttributeType => "attributetype",
            EntryClass::Class => ATTR_CLASS,
            EntryClass::ClassType => "classtype",
            EntryClass::Conflict => "conflict",
            EntryClass::DomainInfo => "domain_info",
            EntryClass::DynGroup => ATTR_DYNGROUP,
            EntryClass::ExtensibleObject => "extensibleobject",
            EntryClass::Group => ATTR_GROUP,
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
            EntryClass::SourceUuid => CLASS_SOURCEUUID,
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
        (Attribute::Class.as_str(), EntryClass::Account.to_value()),
        (Attribute::Class.as_str(), EntryClass::MemberOf.to_value()),
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (
            Attribute::Class.as_str(),
            EntryClass::ServiceAccount.to_value()
        ),
        (Attribute::Name.as_str(), Value::new_iname("admin")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_ADMIN)),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s("Builtin System Admin account.")
        ),
        (
            Attribute::DisplayName.as_str(),
            Value::new_utf8s("System Administrator")
        )
    );
}

lazy_static! {
    /// Builtin IDM Admin account.
    pub static ref E_IDM_ADMIN_V1: EntryInitNew = entry_init!(
        (Attribute::Class.as_str(), EntryClass::Account.to_value()),
        (Attribute::Class.as_str(), EntryClass::MemberOf.to_value()),
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Class.as_str(), EntryClass::ServiceAccount.to_value()),
        (Attribute::Name.as_str(), Value::new_iname("idm_admin")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_IDM_ADMIN)),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Admin account.")
        ),
        (Attribute::DisplayName.as_str(), Value::new_utf8s("IDM Administrator"))
    );
}

#[derive(Clone, Debug)]
pub struct SchemaGroup {
    pub name: &'static str,
    description: &'static str,
    classes: Vec<EntryClass>,
    uuid: uuid::Uuid,
    member: uuid::Uuid,
}

impl Into<EntryInitNew> for SchemaGroup {
    fn into(self) -> EntryInitNew {
        let mut entry = EntryInitNew::new();

        entry.add_ava(Attribute::Name.as_str(), Value::new_iname(self.name));
        entry.add_ava(
            Attribute::Description.as_str(),
            Value::new_utf8s(self.description),
        );
        // classes
        entry.set_ava(
            Attribute::Class.as_str(),
            self.classes
                .into_iter()
                .map(|class| class.to_value())
                .collect::<Vec<Value>>(),
        );
        entry.add_ava(Attribute::Uuid.as_str(), Value::Uuid(self.uuid));
        entry.add_ava(Attribute::Member.as_str(), Value::Refer(self.member));
        entry
    }
}

lazy_static! {
    pub static ref IDM_ADMINS_V1: SchemaGroup = SchemaGroup {
        name: "idm_admins",
        description: "Builtin IDM Administrators Group.",
        classes: vec![
            EntryClass::Group,
            EntryClass::Object,
        ],
        uuid: UUID_IDM_ADMINS,
        member: UUID_IDM_ADMIN,
    };
    /// Builtin IDM Administrators Group.
    // pub static ref E_IDM_ADMINS_V1: EntryInitNew = IDM_ADMINS_V1.clone().into();
    pub static ref E_IDM_ADMINS_V1: EntryInitNew = entry_init!(
        (Attribute::Class.as_str(), EntryClass::Group.to_value()),
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Name.as_str(), Value::new_iname("idm_admins")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_IDM_ADMINS)),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s("Builtin IDM Administrators Group.")
        ),
        (Attribute::Member.as_str(), Value::Refer(UUID_IDM_ADMIN))
    );
}

lazy_static! {
    /// Builtin System Administrators Group.
    pub static ref E_SYSTEM_ADMINS_V1: EntryInitNew = entry_init!(
        (Attribute::Class.as_str(), EntryClass::Group.to_value()),
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Name.as_str(), Value::new_iname("system_admins")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_SYSTEM_ADMINS)),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s("Builtin System Administrators Group.")
        ),
        (Attribute::Member.as_str(), Value::Refer(UUID_ADMIN))
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
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Class.as_str(), EntryClass::Group.to_value()),
        (
            Attribute::Name.as_str(),
            Value::new_iname("idm_ui_enable_experimental_features")
        ),
        (
            Attribute::Uuid.as_str(),
            Value::Uuid(UUID_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES)
        ),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s(
                "Members of this group will have access to experimental web UI features."
            )
        ),
        (Attribute::GrantUiHint .as_str(), Value::UiHint(UiHint::ExperimentalFeatures))
    );

    pub static ref E_IDM_ACCOUNT_MAIL_READ_PRIV: EntryInitNew = entry_init!(
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Class.as_str(), EntryClass::Group.to_value()),
        (
            Attribute::Name.as_str(),
            Value::new_iname("idm_account_mail_read_priv")
        ),
        (
            Attribute::Uuid.as_str(),
            Value::Uuid(UUID_IDM_ACCOUNT_MAIL_READ_PRIV)
        ),
        (
            Attribute::Description.as_str(),
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
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Class.as_str(), EntryClass::SystemInfo.to_value()),
        (Attribute::Class.as_str(), EntryClass::System.to_value()),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_SYSTEM_INFO)),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s("System (local) info and metadata object.")
        ),
        (Attribute::Version.as_str(), Value::Uint32(14))
    );
}

lazy_static! {
    pub static ref E_DOMAIN_INFO_V1: EntryInitNew = entry_init!(
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Class.as_str(), EntryClass::DomainInfo.to_value()),
        (Attribute::Class.as_str(), EntryClass::System.to_value()),
        (Attribute::Name.as_str(), Value::new_iname("domain_local")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_DOMAIN_INFO)),
        (
            Attribute::Description.as_str(),
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
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Class.as_str(), EntryClass::Account.to_value()),
        (
            Attribute::Class.as_str(),
            EntryClass::ServiceAccount.to_value()
        ),
        (Attribute::Name.as_str(), Value::new_iname("anonymous")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_ANONYMOUS)),
        (
            Attribute::Description.as_str(),
            Value::new_utf8s("Anonymous access account.")
        ),
        (
            Attribute::DisplayName.as_str(),
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
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Name.as_str(), Value::new_iname("testperson1")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_TESTPERSON_1))
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        (Attribute::Class.as_str(), EntryClass::Object.to_value()),
        (Attribute::Name.as_str(), Value::new_iname("testperson2")),
        (Attribute::Uuid.as_str(), Value::Uuid(UUID_TESTPERSON_2))
    );
}
