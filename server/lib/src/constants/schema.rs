//! Core Constants
//!
//! Schema uuids start at `00000000-0000-0000-0000-ffff00000000`
//!
use crate::constants::entries::{ValueAttribute, ValueClass};
use crate::constants::uuids::*;
use crate::schema::{SchemaAttribute, SchemaClass};
use crate::value::IndexType;
use crate::value::SyntaxType;

lazy_static!(

pub static ref SCHEMA_ATTR_DISPLAYNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DISPLAYNAME,
    name: ValueAttribute::DisplayName.into(),
    description: "The publicly visible display name of this person".to_string(),

    index: vec![IndexType::Equality],
    sync_allowed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_MAIL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_MAIL,
    name: ValueAttribute::Mail.into(),
    description: "mail addresses of the object".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::EmailAddress,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_EC_KEY_PRIVATE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_EC_KEY_PRIVATE,
    name: ValueAttribute::IdVerificationEcKey.into(),
    description: "Account verification private key.".to_string(),

    index: vec![IndexType::Presence],
    unique: false,
    sync_allowed: false,
    syntax: SyntaxType::EcKeyPrivate,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SSH_PUBLICKEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SSH_PUBLICKEY,
    name: ValueAttribute::SshUnderscorePublicKey.into(),
    description: "SSH public keys of the object".to_string(),

    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::SshKey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PRIMARY_CREDENTIAL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PRIMARY_CREDENTIAL,
    name: ValueAttribute::PrimaryCredential.into(),
    description: "Primary credential material of the account for authentication interactively.to_string().".to_string(),

    index: vec![IndexType::Presence],
    sync_allowed: true,
    syntax: SyntaxType::Credential,
    ..Default::default()
};
pub static ref SCHEMA_ATTR_LEGALNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LEGALNAME,
    name: ValueAttribute::LegalName.into(),
    description: "The private and sensitive legal name of this person".to_string(),

    index: vec![IndexType::Equality],
    sync_allowed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_NAME_HISTORY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_NAME_HISTORY,
    name: ValueAttribute::NameHistory.into(),
    description: "The history of names that a person has had".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::AuditLogString,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_RADIUS_SECRET: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_RADIUS_SECRET,
    name: ValueAttribute::RadiusSecret.into(),
    description: "The accounts generated radius secret for device network authentication".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_NAME,
    name: ValueAttribute::DomainName.into(),
    description: "The domain's DNS name for webauthn and SPN generation purposes.to_string().".to_string(),

    index: vec![IndexType::Equality, IndexType::Presence],
    unique: true,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_LDAP_BASEDN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_LDAP_BASEDN,
    name: ValueAttribute::DomainLdapBasedn.into(),
    description:
        "The domain's optional ldap basedn. If unset defaults to domain components of domain name.".to_string(),

    unique: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_DISPLAY_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_DISPLAY_NAME,
    name: ValueAttribute::DomainDisplayName.into(),
    description: "The user-facing display name of the Kanidm domain.to_string().".to_string(),

    index: vec![IndexType::Equality],
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_UUID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_UUID,
    name: ValueAttribute::DomainUuid.into(),
    description: "The domain's uuid, used in CSN and trust relationships.to_string().".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::Uuid,
    ..Default::default()
};
pub static ref SCHEMA_ATTR_DOMAIN_SSID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_SSID,
    name: ValueAttribute::DomainSsid.into(),
    description: "The domains site-wide SSID for device autoconfiguration of wireless".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_TOKEN_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_TOKEN_KEY,
    name: ValueAttribute::DomainTokenKey.into(),
    description: "The domain token encryption private key (NOT USED).to_string().".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR,
    name: ValueAttribute::FernetPrivateKeyStr.into(),
    description: "The token encryption private key.to_string().".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_GIDNUMBER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_GIDNUMBER,
    name: ValueAttribute::GidNumber.into(),
    description: "The groupid (uid) number of a group or account.to_string(). This is the same value as the UID number on posix accounts for security reasons.".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    sync_allowed: true,
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_BADLIST_PASSWORD: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_BADLIST_PASSWORD,
    name: ValueAttribute::BadlistPassword.into(),
    description: "A password that is badlisted meaning that it can not be set as a valid password by any user account.to_string().".to_string(),

    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LOGINSHELL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LOGINSHELL,
    name: ValueAttribute::LoginShell.into(),
    description: "A POSIX user's UNIX login shell".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_UNIX_PASSWORD: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_UNIX_PASSWORD,
    name: ValueAttribute::UnixPassword.into(),
    description: "A POSIX user's UNIX login password.to_string().".to_string(),

    index: vec![IndexType::Presence],
    syntax: SyntaxType::Credential,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_NSUNIQUEID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_NSUNIQUEID,
    name: ValueAttribute::NsUniqueId.into(),
    description: "A unique id compatibility for 389-ds/dsee".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    sync_allowed: true,
    syntax: SyntaxType::NsUniqueId,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ACCOUNT_EXPIRE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_EXPIRE,
    name: ValueAttribute::AccountExpire.into(),
    description: "The datetime after which this accounnt no longer may authenticate.to_string().".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ACCOUNT_VALID_FROM: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_VALID_FROM,
    name: ValueAttribute::AccountValidFrom.into(),
    description: "The datetime after which this account may commence authenticating.to_string().".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_NAME,
    name: ValueAttribute::OAuth2RsName.into(),
    description: "The unique name of an external Oauth2 resource".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN,
    name: ValueAttribute::OAuth2RsOrigin.into(),
    description: "The origin domain of an oauth2 resource server".to_string(),

    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING,
    name: ValueAttribute::OAuth2RsOriginLanding.into(),
    description: "The landing page of an RS, that will automatically trigger the auth process.to_string().".to_string(),

    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP,
    name: ValueAttribute::OAuth2RsScopeMap.into(),
    description:
        "A reference to a group mapped to scopes for the associated oauth2 resource server".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
    name: ValueAttribute::OAuth2RsSupScopeMap.into(),
    description:
        "A reference to a group mapped to scopes for the associated oauth2 resource server".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET,
    name: ValueAttribute::OAuth2RsBasicSecret.into(),
    description: "When using oauth2 basic authentication, the secret string of the resource server".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY,
    name: ValueAttribute::OAuth2RsTokenKey.into(),
    description: "An oauth2 resource servers unique token signing key".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
    name: ValueAttribute::OAuth2RsImplicitScopes.into(),
    description: "An oauth2 resource servers scopes that are implicitly granted to all users".to_string(),

    multivalue: true,
    syntax: SyntaxType::OauthScope,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP,
    name: ValueAttribute::OAuth2ConsentScopeMap.into(),
    description: "A set of scopes mapped from a relying server to a user, where the user has previously consented to the following. If changed or deleted, consent will be re-sought.".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ES256_PRIVATE_KEY_DER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ES256_PRIVATE_KEY_DER,
    name: ValueAttribute::Es256PrivateKeyDer.into(),
    description: "An es256 private key".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_RS256_PRIVATE_KEY_DER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_RS256_PRIVATE_KEY_DER,
    name: ValueAttribute::Rs256PrivateKeyDer.into(),
    description: "An rs256 private key".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY,
    name: ValueAttribute::JwsEs256PrivateKey.into(),
    description: "An es256 private key for jws".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::JwsKeyEs256,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PRIVATE_COOKIE_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PRIVATE_COOKIE_KEY,
    name: ValueAttribute::PrivateCookieKey.into(),
    description: "An private cookie hmac key".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE,
    name: ValueAttribute::OAuth2AllowInsecureClientDisablePkce.into(),
    description: "Allows disabling of PKCE for insecure OAuth2 clients".to_string(),

    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
    name: ValueAttribute::OAuth2JwtLegacyCryptoEnable.into(),
    description: "Allows enabling legacy JWT cryptograhpy for clients".to_string(),

    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
    name: ValueAttribute::CredentialUpdateIntentToken.into(),
    description: "The status of a credential update intent token".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::IntentToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PASSKEYS: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PASSKEYS,
    name: ValueAttribute::PassKeys.into(),
    description: "A set of registered passkeys".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::Passkey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DEVICEKEYS: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DEVICEKEYS,
    name: ValueAttribute::DeviceKeys.into(),
    description: "A set of registered device keys".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::DeviceKey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DYNGROUP_FILTER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DYNGROUP_FILTER,
    name: ValueAttribute::DynGroupFilter.into(),
    description: "A filter describing the set of entries to add to a dynamic group".to_string(),

    syntax: SyntaxType::JsonFilter,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME,
    name: ValueAttribute::OAuth2PreferShortUsername.into(),
    description: "Use 'name' instead of 'spn' in the preferred_username claim".to_string(),

    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_API_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_API_TOKEN_SESSION,
    name: ValueAttribute::ApiTokenSession.into(),
    description: "A session entry related to an issued API token".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION,
    name: ValueAttribute::UserAuthTokenSession.into(),
    description: "A session entry related to an issued user auth token".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    syntax: SyntaxType::Session,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_SESSION,
    name: ValueAttribute::OAuth2Session.into(),
    description: "A session entry to an active oauth2 session, bound to a parent user auth token".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::Oauth2Session,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_TOKEN_SESSION,
    name: ValueAttribute::SyncTokenSession.into(),
    description: "A session entry related to an issued sync token".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_COOKIE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_COOKIE,
    name: ValueAttribute::SyncCookie.into(),
    description: "A private sync cookie for a remote IDM source".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_GRANT_UI_HINT: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_GRANT_UI_HINT,
    name: ValueAttribute::GrantUiHint.into(),
    description: "A UI hint that is granted via membership to a group".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::UiHint,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL,
    name: ValueAttribute::SyncCredentialPortal.into(),
    description: "The url of an external credential portal for synced accounts to visit to update their credentials.to_string().".to_string(),

    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_YIELD_AUTHORITY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_YIELD_AUTHORITY,
    name: ValueAttribute::SyncYieldAuthority.into(),
    description: "A set of attributes that have their authority yielded to Kanidm in a sync agreement.to_string().".to_string(),

    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

// === classes ===

pub static ref SCHEMA_CLASS_PERSON: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_PERSON,
    name: ValueClass::Person.into(),
    description: "Object representation of a person".to_string(),

    sync_allowed: true,
    systemmay: vec![
        ValueAttribute::Mail.into(),
        ValueAttribute::LegalName.into(),
        ],
    systemmust: vec![
        ValueAttribute::DisplayName.into(),
        ValueAttribute::Name.into(),
        ValueAttribute::IdVerificationEcKey.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ORGPERSON: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ORGPERSON,
    name: ValueClass::OrgPerson.into(),
    description: "Object representation of an org person".to_string(),

    systemmay: vec![
        ValueAttribute::LegalName.into()
        ],
    systemmust: vec![
        ValueAttribute::Mail.into(),
        ValueAttribute::DisplayName.into(),
        ValueAttribute::Name.into()
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_GROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_GROUP,
    name: ValueClass::Group.into(),
    description: "Object representation of a group".to_string(),

    sync_allowed: true,
    systemmay: vec![
        ValueAttribute::Member.into(),
        ValueAttribute::GrantUiHint.into(),
        ValueAttribute::Description.into()
    ],
    systemmust: vec![
        ValueAttribute::Name.into(),
        ValueAttribute::Spn.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_DYNGROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DYNGROUP,
    name: ValueClass::DynGroup.into(),
    description: "Object representation of a dynamic group".to_string(),

    systemmust: vec![ValueAttribute::DynGroupFilter.into()],
    systemmay: vec![ValueAttribute::DynMember.into()],
    systemsupplements: vec![ValueAttribute::Group.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ACCOUNT,
    name: ValueClass::Account.into(),
    description: "Object representation of an account".to_string(),

    sync_allowed: true,
    systemmay: vec![
        ValueAttribute::PrimaryCredential.into(),
        ValueAttribute::PassKeys.into(),
        ValueAttribute::DeviceKeys.into(),
        ValueAttribute::CredentialUpdateIntentToken.into(),
        ValueAttribute::SshUnderscorePublicKey.into(),
        ValueAttribute::RadiusSecret.into(),
        ValueAttribute::AccountExpire.into(),
        ValueAttribute::AccountValidFrom.into(),
        ValueAttribute::Mail.into(),
        ValueAttribute::OAuth2ConsentScopeMap.into(),
        ValueAttribute::UserAuthTokenSession.into(),
        ValueAttribute::OAuth2Session.into(),
        ValueAttribute::Description.into(),
        ValueAttribute::NameHistory.into(),
    ],
    systemmust: vec![
            ValueAttribute::DisplayName.into(),
            ValueAttribute::Name.into(),
            ValueAttribute::Spn.into()
            ],
    systemsupplements: vec![
        ValueClass::Person.into(),
        ValueClass::ServiceAccount.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SERVICE_ACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SERVICE_ACCOUNT,
    name: ValueClass::ServiceAccount.into(),
    description: "Object representation of service account".to_string(),

    sync_allowed: true,
    systemmay: vec![
        ValueAttribute::Mail.into(),
        ValueAttribute::PrimaryCredential.into(),
        ValueAttribute::JwsEs256PrivateKey.into(),
        ValueAttribute::ApiTokenSession.into(),
    ],
    systemexcludes: vec![ValueClass::Person.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SYNC_ACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SYNC_ACCOUNT,
    name: ValueClass::SyncAccount.into(),
    description: "Object representation of sync account".to_string(),

    systemmust: vec![ValueAttribute::Name.into(), ValueAttribute::JwsEs256PrivateKey.into()],
    systemmay: vec![
        ValueAttribute::SyncTokenSession.into(),
        ValueAttribute::SyncCookie.into(),
        ValueAttribute::SyncCredentialPortal.into(),
        ValueAttribute::SyncYieldAuthority.into(),
    ],
    systemexcludes: vec![ValueClass::Account.into()],
    ..Default::default()
};

// domain_info type
//  domain_uuid
//  domain_name <- should be the dns name?
//  domain_ssid <- for radius
//
pub static ref SCHEMA_CLASS_DOMAIN_INFO: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DOMAIN_INFO,
    name: ValueClass::DomainInfo.into(),
    description: "Local domain information and partial configuration.to_string().".to_string(),

    systemmay: vec![ValueAttribute::DomainSsid.into(), ValueAttribute::DomainLdapBasedn.into()],
    systemmust: vec![
        ValueAttribute::Name.into(),
        ValueAttribute::DomainUuid.into(),
        ValueAttribute::DomainName.into(),
        ValueAttribute::DomainDisplayName.into(),
        ValueAttribute::FernetPrivateKeyStr.into(),
        ValueAttribute::Es256PrivateKeyDer.into(),
        ValueAttribute::PrivateCookieKey.into(),
        ValueAttribute::Version.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_POSIXGROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_POSIXGROUP,
    name: ValueClass::PosixGroup.into(),
    description: "Object representation of a posix group, requires group".to_string(),

    sync_allowed: true,
    systemmust: vec![ValueAttribute::GidNumber.into()],
    systemsupplements: vec![ValueAttribute::Group.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_POSIXACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_POSIXACCOUNT,
    name: ValueClass::PosixAccount.into(),
    description: "Object representation of a posix account, requires account".to_string(),

    sync_allowed: true,
    systemmay: vec![ValueAttribute::LoginShell.into(), ValueAttribute::UnixPassword.into()],
    systemmust: vec![ValueAttribute::GidNumber.into()],
    systemsupplements: vec![ValueAttribute::Account.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SYSTEM_CONFIG: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SYSTEM_CONFIG,
    name: ValueClass::SystemConfig.into(),
    description: "The class representing a system (topologies) configuration options.to_string().".to_string(),

    systemmay: vec![
        ValueAttribute::Description.into(),
        ValueAttribute::BadlistPassword.into(),
        ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_OAUTH2_RS: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS,
    name: ValueClass::OAuth2ResourceServer.into(),
    description: "The class representing a configured Oauth2 Resource Server".to_string(),

    systemmay: vec![
        ValueAttribute::Description.into(),
        ValueAttribute::OAuth2RsScopeMap.into(),
        ValueAttribute::OAuth2RsSupScopeMap.into(),
        ValueAttribute::Rs256PrivateKeyDer.into(),
        ValueAttribute::OAuth2JwtLegacyCryptoEnable.into(),
        ValueAttribute::OAuth2PreferShortUsername.into(),
        ValueAttribute::OAuth2RsOriginLanding.into(),
    ],
    systemmust: vec![
        ValueAttribute::OAuth2RsName.into(),
        ValueAttribute::DisplayName.into(),
        ValueAttribute::OAuth2RsOrigin.into(),
        ValueAttribute::OAuth2RsTokenKey.into(),
        ValueAttribute::Es256PrivateKeyDer.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_OAUTH2_RS_BASIC: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_BASIC,
    name: ValueClass::OAuth2ResourceServerBasic.into(),
    description: "The class representing a configured Oauth2 Resource Server authenticated with http basic authentication".to_string(),

    systemmay: vec![ ValueAttribute::OAuth2AllowInsecureClientDisablePkce.into()],
    systemmust: vec![ ValueAttribute::OAuth2RsBasicSecret.into()],
    // TODO: is this a class exclude or an attribute exclude?
    systemexcludes: vec![ ValueClass::OAuth2ResourceServerPublic.into()],
    ..Default::default()
};


pub static ref SCHEMA_CLASS_OAUTH2_RS_PUBLIC: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_PUBLIC,
    name: ValueClass::OAuth2ResourceServerPublic.into(),

    description: "The class representing a configured Oauth2 Resource Server with public clients and pkce verification".to_string(),
    // TODO: is this a class exclude or an attribute exclude, or both?
    systemexcludes: vec![ValueClass::OAuth2ResourceServerBasic.into()],
    ..Default::default()
};

);
