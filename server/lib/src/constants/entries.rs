//! Constant Entries for the IDM
use enum_iterator::Sequence;

use std::fmt::Display;

use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::idm::account::Account;
use crate::value::PartialValue;
use crate::value::Value;
use kanidm_proto::constants::*;
use kanidm_proto::v1::{Filter, OperationError, UiHint};

#[cfg(test)]
use uuid::uuid;

use uuid::Uuid;

#[test]
fn test_valueattribute_as_str() {
    assert!(Attribute::Class.as_ref() == "class");
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
    AcpReceiver,
    AcpReceiverGroup,
    AcpSearchAttr,
    AcpTargetScope,
    ApiTokenSession,
    Attr,
    AttributeName,
    AttributeType,
    AuthSessionExpiry,
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
    Dn,
    Domain,
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
    EntryDn,
    EntryUuid,
    Es256PrivateKeyDer,
    Excludes,
    FernetPrivateKeyStr,
    GidNumber,
    GrantUiHint,
    Group,
    IdVerificationEcKey,
    Index,
    IpaNtHash,
    JwsEs256PrivateKey,
    LastModifiedCid,
    /// An LDAP Compatible emailAddress
    LdapEmailAddress,
    /// An LDAP Compatible sshkeys virtual attribute
    LdapKeys,
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
    PrivilegeExpiry,
    RadiusSecret,
    Replicated,
    Rs256PrivateKeyDer,
    Scope,
    SourceUuid,
    Spn,
    /// An LDAP-compatible sshpublickey
    LdapSshPublicKey,
    /// The Kanidm-local ssh_publickey
    SshPublicKey,
    Supplements,
    SystemSupplements,
    SyncAllowed,
    SyncClass,
    SyncCookie,
    SyncCredentialPortal,
    SyncExternalId,
    SyncParentUuid,
    SyncTokenSession,
    SyncYieldAuthority,
    Syntax,
    SystemExcludes,
    SystemMay,
    SystemMust,
    Term,
    TotpImport,
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
    TestNumber,
    #[cfg(any(debug_assertions, test))]
    Extra,
    #[cfg(any(debug_assertions, test))]
    TestNotAllowed,
}

impl AsRef<str> for Attribute {
    fn as_ref(&self) -> &str {
        self.into()
    }
}

impl From<&Attribute> for &'static str {
    fn from(value: &Attribute) -> Self {
        (*value).into()
    }
}

impl TryFrom<&str> for Attribute {
    type Error = OperationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Attribute::try_from(value.to_string())
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
            ATTR_ACP_RECEIVER => Attribute::AcpReceiver,
            ATTR_ACP_RECEIVER_GROUP => Attribute::AcpReceiverGroup,
            ATTR_ACP_SEARCH_ATTR => Attribute::AcpSearchAttr,
            ATTR_ACP_TARGET_SCOPE => Attribute::AcpTargetScope,
            ATTR_API_TOKEN_SESSION => Attribute::ApiTokenSession,
            ATTR_ATTR => Attribute::Attr,
            ATTR_ATTRIBUTENAME => Attribute::AttributeName,
            ATTR_ATTRIBUTETYPE => Attribute::AttributeType,
            ATTR_AUTH_SESSION_EXPIRY => Attribute::AuthSessionExpiry,
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
            ATTR_DN => Attribute::Dn,
            ATTR_DOMAIN => Attribute::Domain,
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
            ATTR_ENTRYDN => Attribute::EntryDn,
            ATTR_ENTRYUUID => Attribute::EntryUuid,
            ATTR_ES256_PRIVATE_KEY_DER => Attribute::Es256PrivateKeyDer,
            ATTR_EXCLUDES => Attribute::Excludes,
            ATTR_FERNET_PRIVATE_KEY_STR => Attribute::FernetPrivateKeyStr,
            ATTR_GIDNUMBER => Attribute::GidNumber,
            ATTR_GRANT_UI_HINT => Attribute::GrantUiHint,
            ATTR_GROUP => Attribute::Group,
            ATTR_ID_VERIFICATION_ECKEY => Attribute::IdVerificationEcKey,
            ATTR_INDEX => Attribute::Index,
            ATTR_IPANTHASH => Attribute::IpaNtHash,
            ATTR_JWS_ES256_PRIVATE_KEY => Attribute::JwsEs256PrivateKey,
            ATTR_LAST_MODIFIED_CID => Attribute::LastModifiedCid,
            ATTR_LDAP_EMAIL_ADDRESS => Attribute::LdapEmailAddress,
            ATTR_LDAP_KEYS => Attribute::LdapKeys,
            ATTR_LDAP_SSH_PUBLICKEY => Attribute::SshPublicKey,
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
            ATTR_PRIVILEGE_EXPIRY => Attribute::PrivilegeExpiry,
            ATTR_RADIUS_SECRET => Attribute::RadiusSecret,
            ATTR_REPLICATED => Attribute::Replicated,
            ATTR_RS256_PRIVATE_KEY_DER => Attribute::Rs256PrivateKeyDer,
            ATTR_SCOPE => Attribute::Scope,
            ATTR_SOURCE_UUID => Attribute::SourceUuid,
            ATTR_SPN => Attribute::Spn,
            ATTR_SSHPUBLICKEY => Attribute::LdapSshPublicKey,
            ATTR_SUPPLEMENTS => Attribute::Supplements,
            ATTR_SYNC_ALLOWED => Attribute::SyncAllowed,
            ATTR_SYNC_CLASS => Attribute::SyncClass,
            ATTR_SYNC_COOKIE => Attribute::SyncCookie,
            ATTR_SYNC_CREDENTIAL_PORTAL => Attribute::SyncCredentialPortal,
            ATTR_SYNC_EXTERNAL_ID => Attribute::SyncExternalId,
            ATTR_SYNC_PARENT_UUID => Attribute::SyncParentUuid,
            ATTR_SYNC_TOKEN_SESSION => Attribute::SyncTokenSession,
            ATTR_SYNC_YIELD_AUTHORITY => Attribute::SyncYieldAuthority,
            ATTR_SYNTAX => Attribute::Syntax,
            ATTR_SYSTEMEXCLUDES => Attribute::SystemExcludes,
            ATTR_SYSTEMMAY => Attribute::SystemMay,
            ATTR_SYSTEMMUST => Attribute::SystemMust,
            ATTR_SYSTEMSUPPLEMENTS => Attribute::SystemSupplements,
            ATTR_TERM => Attribute::Term,
            ATTR_TOTP_IMPORT => Attribute::TotpImport,
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
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NUMBER => Attribute::TestNumber,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NOTALLOWED => Attribute::TestNotAllowed,
            _ => return Err(OperationError::InvalidAttributeName(val)),
        };
        Ok(res)
    }
}

impl From<Attribute> for &'static str {
    fn from(val: Attribute) -> Self {
        match val {
            Attribute::Account => ATTR_ACCOUNT,
            Attribute::AccountExpire => ATTR_ACCOUNT_EXPIRE,
            Attribute::AccountValidFrom => ATTR_ACCOUNT_VALID_FROM,
            Attribute::AcpCreateAttr => ATTR_ACP_CREATE_ATTR,
            Attribute::AcpCreateClass => ATTR_ACP_CREATE_CLASS,
            Attribute::AcpEnable => ATTR_ACP_ENABLE,
            Attribute::AcpModifyClass => ATTR_ACP_MODIFY_CLASS,
            Attribute::AcpModifyPresentAttr => ATTR_ACP_MODIFY_PRESENTATTR,
            Attribute::AcpModifyRemovedAttr => ATTR_ACP_MODIFY_REMOVEDATTR,
            Attribute::AcpReceiver => ATTR_ACP_RECEIVER,
            Attribute::AcpReceiverGroup => ATTR_ACP_RECEIVER_GROUP,
            Attribute::AcpSearchAttr => ATTR_ACP_SEARCH_ATTR,
            Attribute::AcpTargetScope => ATTR_ACP_TARGET_SCOPE,
            Attribute::ApiTokenSession => ATTR_API_TOKEN_SESSION,
            Attribute::Attr => ATTR_ATTR,
            Attribute::AttributeName => ATTR_ATTRIBUTENAME,
            Attribute::AttributeType => ATTR_ATTRIBUTETYPE,
            Attribute::AuthSessionExpiry => ATTR_AUTH_SESSION_EXPIRY,
            Attribute::BadlistPassword => ATTR_BADLIST_PASSWORD,
            Attribute::Claim => ATTR_CLAIM,
            Attribute::Class => ATTR_CLASS,
            Attribute::ClassName => ATTR_CLASSNAME,
            Attribute::Cn => ATTR_CN,
            Attribute::CookiePrivateKey => ATTR_COOKIE_PRIVATE_KEY,
            Attribute::CredentialUpdateIntentToken => ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
            Attribute::Description => ATTR_DESCRIPTION,
            Attribute::DeviceKeys => ATTR_DEVICEKEYS,
            Attribute::DirectMemberOf => ATTR_DIRECTMEMBEROF,
            Attribute::DisplayName => ATTR_DISPLAYNAME,
            Attribute::Dn => ATTR_DN,
            Attribute::Domain => ATTR_DOMAIN,
            Attribute::DomainDisplayName => ATTR_DOMAIN_DISPLAY_NAME,
            Attribute::DomainLdapBasedn => ATTR_DOMAIN_LDAP_BASEDN,
            Attribute::DomainName => ATTR_DOMAIN_NAME,
            Attribute::DomainSsid => ATTR_DOMAIN_SSID,
            Attribute::DomainTokenKey => ATTR_DOMAIN_TOKEN_KEY,
            Attribute::DomainUuid => ATTR_DOMAIN_UUID,
            Attribute::DynGroup => ATTR_DYNGROUP,
            Attribute::DynGroupFilter => ATTR_DYNGROUP_FILTER,
            Attribute::DynMember => ATTR_DYNMEMBER,
            Attribute::Email => ATTR_EMAIL,
            Attribute::EmailAlternative => ATTR_EMAIL_ALTERNATIVE,
            Attribute::EmailPrimary => ATTR_EMAIL_PRIMARY,
            Attribute::EntryDn => ATTR_ENTRYDN,
            Attribute::EntryUuid => ATTR_ENTRYUUID,
            Attribute::Es256PrivateKeyDer => ATTR_ES256_PRIVATE_KEY_DER,
            Attribute::Excludes => ATTR_EXCLUDES,
            Attribute::FernetPrivateKeyStr => ATTR_FERNET_PRIVATE_KEY_STR,
            Attribute::GidNumber => ATTR_GIDNUMBER,
            Attribute::GrantUiHint => ATTR_GRANT_UI_HINT,
            Attribute::Group => ATTR_GROUP,
            Attribute::IdVerificationEcKey => ATTR_ID_VERIFICATION_ECKEY,
            Attribute::Index => ATTR_INDEX,
            Attribute::IpaNtHash => ATTR_IPANTHASH,
            Attribute::JwsEs256PrivateKey => ATTR_JWS_ES256_PRIVATE_KEY,
            Attribute::LastModifiedCid => ATTR_LAST_MODIFIED_CID,
            Attribute::LdapEmailAddress => ATTR_LDAP_EMAIL_ADDRESS,
            Attribute::LdapKeys => ATTR_LDAP_KEYS,
            Attribute::LdapSshPublicKey => ATTR_SSHPUBLICKEY,
            Attribute::LegalName => ATTR_LEGALNAME,
            Attribute::LoginShell => ATTR_LOGINSHELL,
            Attribute::Mail => ATTR_MAIL,
            Attribute::May => ATTR_MAY,
            Attribute::Member => ATTR_MEMBER,
            Attribute::MemberOf => ATTR_MEMBEROF,
            Attribute::MultiValue => ATTR_MULTIVALUE,
            Attribute::Must => ATTR_MUST,
            Attribute::Name => ATTR_NAME,
            Attribute::NameHistory => ATTR_NAME_HISTORY,
            Attribute::NoIndex => ATTR_NO_INDEX,
            Attribute::NsUniqueId => ATTR_NSUNIQUEID,
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
            Attribute::PrivilegeExpiry => ATTR_PRIVILEGE_EXPIRY,
            Attribute::RadiusSecret => ATTR_RADIUS_SECRET,
            Attribute::Replicated => ATTR_REPLICATED,
            Attribute::Rs256PrivateKeyDer => ATTR_RS256_PRIVATE_KEY_DER,
            Attribute::Scope => ATTR_SCOPE,
            Attribute::SourceUuid => ATTR_SOURCE_UUID,
            Attribute::Spn => ATTR_SPN,
            Attribute::SshPublicKey => ATTR_LDAP_SSH_PUBLICKEY,
            Attribute::Supplements => ATTR_SUPPLEMENTS,
            Attribute::SyncAllowed => ATTR_SYNC_ALLOWED,
            Attribute::SyncClass => ATTR_SYNC_CLASS,
            Attribute::SyncCookie => ATTR_SYNC_COOKIE,
            Attribute::SyncCredentialPortal => ATTR_SYNC_CREDENTIAL_PORTAL,
            Attribute::SyncExternalId => ATTR_SYNC_EXTERNAL_ID,
            Attribute::SyncParentUuid => ATTR_SYNC_PARENT_UUID,
            Attribute::SyncTokenSession => ATTR_SYNC_TOKEN_SESSION,
            Attribute::SyncYieldAuthority => ATTR_SYNC_YIELD_AUTHORITY,
            Attribute::Syntax => ATTR_SYNTAX,
            Attribute::SystemExcludes => ATTR_SYSTEMEXCLUDES,
            Attribute::SystemMay => ATTR_SYSTEMMAY,
            Attribute::SystemMust => ATTR_SYSTEMMUST,
            Attribute::SystemSupplements => ATTR_SYSTEMSUPPLEMENTS,
            Attribute::Term => ATTR_TERM,
            Attribute::TotpImport => ATTR_TOTP_IMPORT,
            Attribute::Uid => ATTR_UID,
            Attribute::UidNumber => ATTR_UIDNUMBER,
            Attribute::Unique => ATTR_UNIQUE,
            Attribute::UnixPassword => ATTR_UNIX_PASSWORD,
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
            #[cfg(any(debug_assertions, test))]
            Attribute::TestNumber => TEST_ATTR_NUMBER,
            #[cfg(any(debug_assertions, test))]
            Attribute::TestNotAllowed => TEST_ATTR_NOTALLOWED,
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

#[derive(Clone, Debug, Default)]
/// Built-in group definitions
pub struct BuiltinGroup {
    pub name: &'static str,
    description: &'static str,
    uuid: uuid::Uuid,
    members: Vec<uuid::Uuid>,
    dyngroup: bool,
    dyngroup_filter: Option<Filter>,
    // TODO: additional attributes (for things like the uihint group)
    extra_attributes: Vec<(Attribute, Value)>,
}

impl TryFrom<BuiltinGroup> for EntryInitNew {
    type Error = OperationError;

    fn try_from(val: BuiltinGroup) -> Result<Self, OperationError> {
        let mut entry = EntryInitNew::new();

        entry.add_ava(Attribute::Name.as_ref(), Value::new_iname(val.name));
        entry.add_ava(
            Attribute::Description.as_ref(),
            Value::new_utf8s(val.description),
        );
        // classes for groups
        entry.set_ava(
            Attribute::Class.as_ref(),
            vec![EntryClass::Group.into(), EntryClass::Object.into()],
        );
        if val.dyngroup {
            entry.add_ava(Attribute::Class.as_ref(), EntryClass::DynGroup.to_value());
            match val.dyngroup_filter {
                Some(filter) => {
                    entry.add_ava(Attribute::DynGroupFilter.as_ref(), Value::JsonFilt(filter))
                }
                None => {
                    error!(
                        "No filter specified for dyngroup '{}' this is going to break things!",
                        val.name
                    );
                    return Err(OperationError::FilterGeneration);
                }
            };
        }
        entry.add_ava(Attribute::Uuid.as_ref(), Value::Uuid(val.uuid));
        entry.set_ava(
            Attribute::Member.as_ref(),
            val.members
                .into_iter()
                .map(Value::Refer)
                .collect::<Vec<Value>>(),
        );
        // add any extra attributes
        val.extra_attributes
            .into_iter()
            .for_each(|(attr, val)| entry.add_ava(attr.as_ref(), val));
        // all done!
        Ok(entry)
    }
}

lazy_static! {
      /// Builtin System Admin account.
      pub static ref BUILTIN_ACCOUNT_IDM_ADMIN: BuiltinAccount = BuiltinAccount {
       // TODO: this really should be a "are you a service account or a person" enum
        classes: vec![
            EntryClass::Account,
            EntryClass::ServiceAccount,
            EntryClass::MemberOf,
            EntryClass::Object,
        ],
        name: "idm_admin",
        uuid: UUID_IDM_ADMIN,
        description: "Builtin IDM Admin account.",
        displayname: "IDM Administrator",
    };
}

lazy_static! {
    /// Builtin IDM Administrators Group.
    pub static ref BUILTIN_GROUP_IDM_ADMINS_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_admins",
        description: "Builtin IDM Administrators Group.",
        uuid: UUID_IDM_ADMINS,
        members: vec![UUID_IDM_ADMIN],
        ..Default::default()
    };

    pub static ref BUILTIN_GROUP_SYSTEM_ADMINS_V1: BuiltinGroup = BuiltinGroup {
        name: "system_admins",
        description: "Builtin System Administrators Group.",
        uuid: UUID_SYSTEM_ADMINS,
        members: vec![BUILTIN_ACCOUNT_ADMIN.uuid],
        ..Default::default()
    };

}

// * People read managers

// pub const JSON_IDM_PEOPLE_READ_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_people_read_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000002"],
//         "description": ["Builtin IDM Group for granting elevated people (personal data) read permissions."],
//         "member": ["00000000-0000-0000-0000-000000000003"]
//     }
// }"#;

lazy_static! {

    /// Builtin IDM Group for granting elevated people (personal data) read permissions.
    pub static ref IDM_PEOPLE_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_read_priv",
        description: "Builtin IDM Group for granting elevated people (personal data) read permissions.",
        uuid: UUID_IDM_PEOPLE_READ_PRIV,
        members: vec![UUID_IDM_PEOPLE_WRITE_PRIV],
        ..Default::default()
    };
    pub static ref IDM_PEOPLE_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_write_priv",
        description: "Builtin IDM Group for granting elevated people (personal data) write permissions.",
        uuid: UUID_IDM_PEOPLE_WRITE_PRIV,
        members: vec![UUID_IDM_PEOPLE_MANAGE_PRIV,UUID_IDM_PEOPLE_EXTEND_PRIV],
        ..Default::default()
    };

/// Builtin IDM Group for granting elevated people (personal data) write permissions.
// pub const JSON_IDM_PEOPLE_WRITE_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_people_write_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000003"],
//         "description": ["Builtin IDM Group for granting elevated people (personal data) write permissions."],
//         "member": [
//             "00000000-0000-0000-0000-000000000013",
//             "00000000-0000-0000-0000-000000000024"
//         ]
//     }
// }"#;

    // * People write managers
    /// Builtin IDM Group for granting elevated people (personal data) write and lifecycle management permissions.
    pub static ref IDM_PEOPLE_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_manage_priv",
        description: "Builtin IDM Group for granting elevated people (personal data) write and lifecycle management permissions.",
        uuid: UUID_IDM_PEOPLE_MANAGE_PRIV,
        members: vec![UUID_IDM_ADMINS],
        ..Default::default()
    };

    /// Builtin IDM Group for importing passwords to person accounts - intended for service account membership only.
    pub static ref IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_account_password_import_priv",
        description: "Builtin IDM Group for importing passwords to person accounts - intended for service account membership only.",
        uuid: UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV,
        members: vec![UUID_IDM_ADMINS],
        ..Default::default()
    };
}

lazy_static! {
    /// Builtin IDM Group for allowing the ability to extend accounts to have the "person" flag set.
    pub static ref IDM_PEOPLE_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_extend_priv",
        description: "Builtin System Administrators Group.",
        uuid: UUID_IDM_PEOPLE_EXTEND_PRIV,
        members: vec![BUILTIN_ACCOUNT_ADMIN.uuid],
        ..Default::default()
    };
}

// pub const JSON_IDM_PEOPLE_EXTEND_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_people_extend_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000024"],
//         "description": ["Builtin IDM Group for extending accounts to be people."],
//         "member": [
//             "00000000-0000-0000-0000-000000000001"
//         ]
//     }
// }"#;

lazy_static! {
    /// Self-write of mail
    pub static ref IDM_PEOPLE_SELF_WRITE_MAIL_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_people_self_write_mail_priv",
        description: "Builtin IDM Group for people accounts to update their own mail.",
        uuid: UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV,
        members: Vec::new(),
        ..Default::default()
    };
}

// pub const JSON_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_people_self_write_mail_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000033"],
//         "description": ["Builtin IDM Group for people accounts to update their own mail."]
//     }
// }"#;

lazy_static! {
    /// Builtin IDM Group for granting elevated high privilege people (personal data) read permissions.
    pub static ref IDM_HP_PEOPLE_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_people_read_priv",
        description: "Builtin IDM Group for granting elevated high privilege people (personal data) read permissions.",
        uuid: UUID_IDM_HP_PEOPLE_READ_PRIV,
        members: vec![UUID_IDM_HP_PEOPLE_WRITE_PRIV],
        ..Default::default()
    };
}
// pub const JSON_IDM_HP_PEOPLE_READ_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_hp_people_read_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000028"],
//         "description": ["Builtin IDM Group for granting elevated high privilege people (personal data) read permissions."],
//         "member": ["00000000-0000-0000-0000-000000000029"]
//     }
// }"#;

// pub const JSON_IDM_HP_PEOPLE_WRITE_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_hp_people_write_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000029"],
//         "description": ["Builtin IDM Group for granting elevated high privilege people (personal data) write permissions."],
//         "member": [
//             "00000000-0000-0000-0000-000000000030"
//         ]
//     }
// }"#;

lazy_static! {
    /// Builtin IDM Group for granting elevated high privilege people (personal data) write permissions.
    pub static ref IDM_HP_PEOPLE_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_people_write_priv",
        description: "Builtin IDM Group for granting elevated high privilege people (personal data) write permissions.",
        uuid: UUID_IDM_HP_PEOPLE_WRITE_PRIV,
        members: vec![UUID_IDM_HP_PEOPLE_EXTEND_PRIV],
        ..Default::default()
    };
    /// Builtin IDM Group for extending high privilege accounts to be people.
    pub static ref IDM_HP_PEOPLE_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_people_extend_priv",
        description: "Builtin IDM Group for extending high privilege accounts to be people.",
        uuid: UUID_IDM_HP_PEOPLE_EXTEND_PRIV,
        members: vec![BUILTIN_ACCOUNT_ADMIN.uuid],
        ..Default::default()
    };
}
// pub const JSON_IDM_HP_PEOPLE_EXTEND_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_hp_people_extend_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000030"],
//         "description": ["Builtin IDM Group for extending high privilege accounts to be people."],
//         "member": [
//             "00000000-0000-0000-0000-000000000000"
//         ]
//     }
// }"#;

// * group write manager (no read, everyone has read via the anon, etc)
// IDM_GROUP_CREATE_PRIV
lazy_static! {
    /// Builtin IDM Group for granting elevated group write and lifecycle permissions.
    pub static ref IDM_GROUP_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_group_manage_priv",
        description: "Builtin IDM Group for granting elevated group write and lifecycle permissions.",
        uuid: UUID_IDM_GROUP_MANAGE_PRIV,
        members: vec![
            BUILTIN_GROUP_IDM_ADMINS_V1.uuid,
            BUILTIN_GROUP_SYSTEM_ADMINS_V1.uuid,
        ],
        ..Default::default()
    };
}
// pub const JSON_IDM_GROUP_MANAGE_PRIV_V1: &str = r#"{
//     "attrs": {
//         "class": ["group", "object"],
//         "name": ["idm_group_manage_priv"],
//         "uuid": ["00000000-0000-0000-0000-000000000015"],
//         "description": ["Builtin IDM Group for granting elevated group write and lifecycle permissions."],
//         "member": [
//             "00000000-0000-0000-0000-000000000001",
//             "00000000-0000-0000-0000-000000000019"
//         ]
//     }
// }"#;

lazy_static! {
    /// Builtin IDM Group for granting elevated group write and lifecycle permissions.
    pub static ref IDM_GROUP_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_group_write_priv",
        description: "Builtin IDM Group for granting elevated group write permissions.",
        uuid: UUID_IDM_GROUP_WRITE_PRIV,
        members: vec![
            UUID_IDM_GROUP_MANAGE_PRIV
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting unix group extension permissions.
    pub static ref IDM_GROUP_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_group_unix_extend_priv",
        description: "Builtin IDM Group for granting UNIX group extension permissions.",
        uuid: UUID_IDM_GROUP_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_IDM_ADMINS
        ],
        ..Default::default()
    };

    /// Account read manager
    pub static ref IDM_ACCOUNT_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_read_priv",
        description: "Builtin IDM Group for granting elevated account read permissions.",
        uuid: UUID_IDM_ACCOUNT_READ_PRIV,
        members: vec![
            UUID_IDM_ACCOUNT_WRITE_PRIV,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACCOUNT_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_manage_priv",
        description: "Builtin IDM Group for granting elevated account write and lifecycle permissions.",
        uuid: UUID_IDM_ACCOUNT_MANAGE_PRIV,
        members: vec![
            UUID_IDM_ADMINS,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACCOUNT_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_write_priv",
        description: "Builtin IDM Group for granting elevated account write permissions.",
        uuid: UUID_IDM_ACCOUNT_WRITE_PRIV,
        members: vec![
            UUID_IDM_ACCOUNT_MANAGE_PRIV,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACCOUNT_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_account_unix_extend_priv",
        description: "Builtin IDM Group for granting account unix extend permissions.",
        uuid: UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_IDM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for RADIUS secret write for all non-hp accounts.
    pub static ref IDM_RADIUS_SECRET_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_radius_secret_write_priv",
        description: "Builtin IDM Group for RADIUS secret write for all non-hp accounts.",
        uuid: UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1,
        members: vec![
            UUID_IDM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for RADIUS secret reading for all non-hp accounts.
    pub static ref IDM_RADIUS_SECRET_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_radius_secret_read_priv",
        description: "Builtin IDM Group for RADIUS secret reading for all non-hp accounts.",
        uuid: UUID_IDM_RADIUS_SECRET_READ_PRIV_V1,
        members: vec![
            UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for RADIUS server access delegation.
    pub static ref IDM_RADIUS_SERVERS_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_radius_servers",
        description: "Builtin IDM Group for RADIUS server access delegation.",
        uuid: UUID_IDM_RADIUS_SERVERS,
        members: vec![
        ],
        ..Default::default()
    };

    /// High privilege account read manager
    pub static ref IDM_HP_ACCOUNT_READ_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_read_priv",
        description: "Builtin IDM Group for granting elevated account read permissions over high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_READ_PRIV,
        members: vec![
            UUID_IDM_HP_ACCOUNT_WRITE_PRIV
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated account write permissions over high privilege accounts.
    pub static ref IDM_HP_ACCOUNT_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_manage_priv",
        description: "Builtin IDM Group for granting elevated account write and lifecycle permissions over high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };
    /// Builtin IDM Group for granting elevated account write permissions over high privilege accounts.
    pub static ref IDM_HP_ACCOUNT_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_write_priv",
        description: "Builtin IDM Group for granting elevated account write permissions over high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_WRITE_PRIV,
        members: vec![
            UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting account unix extend permissions for high privilege accounts.
    pub static ref IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_account_unix_extend_priv",
        description: "Builtin IDM Group for granting account UNIX extend permissions for high privilege accounts.",
        uuid: UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// * Schema write manager
    pub static ref IDM_SCHEMA_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_schema_manage_priv",
        description: "Builtin IDM Group for granting elevated schema write and management permissions.",
        uuid: UUID_IDM_SCHEMA_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// ACP read/write manager
    pub static ref IDM_ACP_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_acp_manage_priv",
        description: "Builtin IDM Group for granting control over all access control profile modifications.",
        uuid: UUID_IDM_ACP_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups.
    pub static ref IDM_HP_GROUP_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_group_manage_priv",
        description: "Builtin IDM Group for granting elevated group write and lifecycle privileges for high privilege groups.",
        uuid: UUID_IDM_HP_GROUP_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting elevated group write privileges for high privilege groups.
    pub static ref IDM_HP_GROUP_WRITE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_group_write_priv",
        description: "Builtin IDM Group for granting elevated group write privileges for high privilege groups.",
        uuid: UUID_IDM_HP_GROUP_WRITE_PRIV,
        members: vec![
            UUID_IDM_HP_GROUP_MANAGE_PRIV,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting unix group extension permissions for high privilege groups.
    pub static ref IDM_HP_GROUP_UNIX_EXTEND_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_group_unix_extend_priv",
        description: "Builtin IDM Group for granting unix group extension permissions for high privilege groups.",
        uuid: UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for granting local domain administration rights and trust administration rights
    pub static ref DOMAIN_ADMINS: BuiltinGroup = BuiltinGroup {
        name: "domain_admins",
        description: "Builtin IDM Group for granting local domain administration rights and trust administration rights.",
        uuid: UUID_DOMAIN_ADMINS,
        members: vec![
            UUID_ADMIN,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for managing oauth2 resource server integrations to this authentication domain.
    pub static ref IDM_HP_OAUTH2_MANAGE_PRIV_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_oauth2_manage_priv",
        description: "Builtin IDM Group for managing oauth2 resource server integrations to this authentication domain.",
        uuid: UUID_IDM_HP_OAUTH2_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for allowing migrations of service accounts into persons
    pub static ref IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_service_account_into_person_migrate_priv",
        description:"Builtin IDM Group for allowing migrations of service accounts into persons",
        uuid: UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };


    /// Builtin IDM Group for allowing migrations of service accounts into persons
    pub static ref IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV: BuiltinGroup = BuiltinGroup {
        name: "idm_hp_sync_account_manage_priv",
        description: "Builtin IDM Group for managing synchronisation from external identity sources",
        uuid: UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV,
        members: vec![
            UUID_SYSTEM_ADMINS,
        ],
        ..Default::default()
    };

    /// Builtin IDM Group for extending high privilege accounts to be people.
    pub static ref IDM_ALL_PERSONS: BuiltinGroup = BuiltinGroup {
        name: "idm_all_persons",
        description: "Builtin IDM Group for extending high privilege accounts to be people.",
        uuid: UUID_IDM_ALL_PERSONS,
        members: Vec::new(),
        dyngroup: true,
        dyngroup_filter: Some(
            Filter::And(vec![
                Filter::Eq(Attribute::Class.to_string(), EntryClass::Person.to_string()),
                Filter::Eq(Attribute::Class.to_string(), EntryClass::Account.to_string()),
            ])
        ),
        ..Default::default()
    };

    /// Builtin IDM Group for extending high privilege accounts to be people.
    pub static ref IDM_ALL_ACCOUNTS: BuiltinGroup = BuiltinGroup {
        name: "idm_all_accounts",
        description: "Builtin IDM dynamic group containing all entries that can authenticate.",
        uuid: UUID_IDM_ALL_ACCOUNTS,
        members: Vec::new(),
        dyngroup: true,
        dyngroup_filter: Some(
                Filter::Eq(Attribute::Class.to_string(), EntryClass::Account.to_string()),
        ),
        ..Default::default()
    };


    pub static ref IDM_UI_ENABLE_EXPERIMENTAL_FEATURES: BuiltinGroup = BuiltinGroup {
        name: "idm_ui_enable_experimental_features",
        description: "Members of this group will have access to experimental web UI features.",
        uuid: UUID_IDM_UI_ENABLE_EXPERIMENTAL_FEATURES,
        extra_attributes: vec![
            (Attribute::GrantUiHint, Value::UiHint(UiHint::ExperimentalFeatures))
        ],
        ..Default::default()
    };

    /// Members of this group will have access to read the mail attribute of all persons and service accounts.
    pub static ref IDM_ACCOUNT_MAIL_READ_PRIV: BuiltinGroup = BuiltinGroup {
        name: "idm_account_mail_read_priv",
        description: "Members of this group will have access to read the mail attribute of all persons and service accounts.",
        uuid: UUID_IDM_ACCOUNT_MAIL_READ_PRIV,
        ..Default::default()
    };

    /// This must be the last group to init to include the UUID of the other high priv groups.
    pub static ref IDM_HIGH_PRIVILEGE_V1: BuiltinGroup = BuiltinGroup {
        name: "idm_high_privilege",
        uuid: UUID_IDM_HIGH_PRIVILEGE,
        description: "Builtin IDM provided groups with high levels of access that should be audited and limited in modification.",
        members: vec![
            UUID_IDM_ADMINS,
            UUID_IDM_PEOPLE_READ_PRIV,
            UUID_IDM_PEOPLE_WRITE_PRIV,
            UUID_IDM_GROUP_WRITE_PRIV,
            UUID_IDM_ACCOUNT_READ_PRIV,
            UUID_IDM_ACCOUNT_WRITE_PRIV,
            UUID_IDM_RADIUS_SERVERS,
            UUID_IDM_HP_ACCOUNT_READ_PRIV,
            UUID_IDM_HP_ACCOUNT_WRITE_PRIV,
            UUID_IDM_SCHEMA_MANAGE_PRIV,
            UUID_IDM_ACP_MANAGE_PRIV,
            UUID_IDM_HP_GROUP_WRITE_PRIV,
            UUID_IDM_PEOPLE_MANAGE_PRIV,
            UUID_IDM_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_GROUP_MANAGE_PRIV,
            UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_HP_GROUP_MANAGE_PRIV,
            UUID_SYSTEM_ADMINS,
            UUID_DOMAIN_ADMINS,
            UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV,
            UUID_IDM_PEOPLE_EXTEND_PRIV,
            UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV,
            UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV,
            UUID_IDM_HP_OAUTH2_MANAGE_PRIV,
            UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1,
            UUID_IDM_RADIUS_SECRET_READ_PRIV_V1,
            UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
            UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV,
            UUID_IDM_HIGH_PRIVILEGE,
        ],
        dyngroup: false,
        dyngroup_filter: None,
        extra_attributes: Vec::new(),
    };
}

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
        (Attribute::Class.as_ref(), EntryClass::Object.to_value()),
        (Attribute::Class.as_ref(), EntryClass::SystemInfo.to_value()),
        (Attribute::Class.as_ref(), EntryClass::System.to_value()),
        (Attribute::Uuid.as_ref(), Value::Uuid(UUID_SYSTEM_INFO)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("System (local) info and metadata object.")
        ),
        (Attribute::Version.as_ref(), Value::Uint32(14))
    );
}

lazy_static! {
    pub static ref E_DOMAIN_INFO_V1: EntryInitNew = entry_init!(
        (Attribute::Class.as_ref(), EntryClass::Object.to_value()),
        (Attribute::Class.as_ref(), EntryClass::DomainInfo.to_value()),
        (Attribute::Class.as_ref(), EntryClass::System.to_value()),
        (Attribute::Name.as_ref(), Value::new_iname("domain_local")),
        (Attribute::Uuid.as_ref(), Value::Uuid(UUID_DOMAIN_INFO)),
        (
            Attribute::Description.as_ref(),
            Value::new_utf8s("This local domain's info and metadata object.")
        )
    );
}

#[derive(Debug, Clone)]
/// Built in accounts such as anonymous, idm_admin and admin
pub struct BuiltinAccount {
    // TODO: this really should be a "are you a service account or a person" enum
    pub classes: Vec<EntryClass>,
    pub name: &'static str,
    pub uuid: Uuid,
    pub description: &'static str,
    pub displayname: &'static str,
}

impl Default for BuiltinAccount {
    fn default() -> Self {
        BuiltinAccount {
            classes: [EntryClass::Object].to_vec(),
            name: "",
            uuid: Uuid::new_v4(),
            description: "<set description>",
            displayname: "<set displayname>",
        }
    }
}

impl From<BuiltinAccount> for Account {
    fn from(value: BuiltinAccount) -> Self {
        Account {
            name: value.name.to_string(),
            uuid: value.uuid,
            displayname: value.displayname.to_string(),
            spn: format!("{}@example.com", value.name),
            mail_primary: None,
            mail: Vec::new(),
            ..Default::default()
        }
    }
}

impl From<BuiltinAccount> for EntryInitNew {
    fn from(value: BuiltinAccount) -> Self {
        let mut entry = EntryInitNew::new();
        entry.add_ava(Attribute::Name.as_ref(), Value::new_iname(value.name));
        entry.add_ava(Attribute::Uuid.as_ref(), Value::Uuid(value.uuid));
        entry.add_ava(
            Attribute::Description.as_ref(),
            Value::new_utf8s(value.description),
        );
        entry.add_ava(
            Attribute::DisplayName.as_ref(),
            Value::new_utf8s(value.displayname),
        );

        entry.add_ava(Attribute::Class.as_ref(), EntryClass::Object.to_value());
        entry.add_ava(Attribute::Class.as_ref(), EntryClass::Account.to_value());
        entry.set_ava(
            Attribute::Class.as_ref(),
            value
                .classes
                .into_iter()
                .map(|c| c.to_value())
                .collect::<Vec<Value>>(),
        );

        entry
    }
}

lazy_static! {

    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_ADMIN: BuiltinAccount = BuiltinAccount {
        classes: vec![
            EntryClass::Account,
            EntryClass::ServiceAccount,
            EntryClass::MemberOf,
            EntryClass::Object,
        ],
        name: "admin",
        uuid: UUID_ADMIN,
        description: "Builtin System Admin account.",
        displayname: "System Administrator",
    };
    pub static ref BUILTIN_ACCOUNT_ANONYMOUS_V1: BuiltinAccount = BuiltinAccount {
        classes: [
            EntryClass::Account,
            EntryClass::ServiceAccount,
            EntryClass::Object,
        ]
        .to_vec(),
        name: "anonymous",
        uuid: UUID_ANONYMOUS,
        description: "Anonymous access account.",
        displayname: "Anonymous",
    };
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
        (Attribute::Class.as_ref(), EntryClass::Object.to_value()),
        (Attribute::Name.as_ref(), Value::new_iname("testperson1")),
        (Attribute::Uuid.as_ref(), Value::Uuid(UUID_TESTPERSON_1))
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        (Attribute::Class.as_ref(), EntryClass::Object.to_value()),
        (Attribute::Name.as_ref(), Value::new_iname("testperson2")),
        (Attribute::Uuid.as_ref(), Value::Uuid(UUID_TESTPERSON_2))
    );
}
