//! Schema Entries
use crate::constants::entries::{Attribute, EntryClass};
use crate::constants::uuids::*;
use crate::schema::{SchemaAttribute, SchemaClass};
use crate::value::SyntaxType;

lazy_static!(

pub static ref SCHEMA_ATTR_DISPLAYNAME_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DISPLAYNAME,
    name: Attribute::DisplayName,
    description: "The publicly visible display name of this person".to_string(),
    indexed: true,
    sync_allowed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_MAIL_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_MAIL,
    name: Attribute::Mail,
    description: "Mail addresses of the object".to_string(),
    indexed: true,
    unique: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::EmailAddress,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_EC_KEY_PRIVATE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_EC_KEY_PRIVATE,
    name: Attribute::IdVerificationEcKey,
    description: "Account verification private key".to_string(),
    indexed: true,
    unique: false,
    sync_allowed: false,
    syntax: SyntaxType::EcKeyPrivate,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SSH_PUBLICKEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SSH_PUBLICKEY,
    name: Attribute::SshPublicKey,
    description: "SSH public keys of the object".to_string(),

    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::SshKey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PRIMARY_CREDENTIAL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PRIMARY_CREDENTIAL,
    name: Attribute::PrimaryCredential,
    description: "Primary credential material of the account for authentication interactively".to_string(),
    indexed: true,
    sync_allowed: true,
    syntax: SyntaxType::Credential,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LEGALNAME_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LEGALNAME,
    name: Attribute::LegalName,
    description: "The private and sensitive legal name of this person".to_string(),
    indexed: true,
    sync_allowed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_NAME_HISTORY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_NAME_HISTORY,
    name: Attribute::NameHistory,
    description: "The history of names that a person has had".to_string(),
    indexed: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::AuditLogString,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_RADIUS_SECRET: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_RADIUS_SECRET,
    name: Attribute::RadiusSecret,
    description: "The accounts generated radius secret for device network authentication".to_string(),
    sync_allowed: true,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_NAME,
    name: Attribute::DomainName,
    description: "The domain's DNS name for webauthn and SPN generation purposes".to_string(),
    indexed: true,
    unique: true,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LDAP_ALLOW_UNIX_PW_BIND: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LDAP_ALLOW_UNIX_PW_BIND,
    name: Attribute::LdapAllowUnixPwBind,
    description: "Configuration to enable binds to LDAP objects using their UNIX password".to_string(),
    unique: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_LDAP_BASEDN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_LDAP_BASEDN,
    name: Attribute::DomainLdapBasedn,
    description: "The domain's optional ldap basedn. If unset defaults to domain components of domain name".to_string(),
    unique: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LDAP_MAXIMUM_QUERYABLE_ATTRIBUTES: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LDAP_MAXIMUM_QUERYABLE_ATTRIBUTES,
    name: Attribute::LdapMaxQueryableAttrs,
    description: "The maximum number of LDAP attributes that can be queried in one operation".to_string(),
    multivalue: false,
    sync_allowed: true,
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_DISPLAY_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_DISPLAY_NAME,
    name: Attribute::DomainDisplayName,
    description: "The user-facing display name of the Kanidm domain".to_string(),
    indexed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_UUID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_UUID,
    name: Attribute::DomainUuid,
    description: "The domain's uuid, used in CSN and trust relationships".to_string(),
    indexed: true,
    unique: true,
    syntax: SyntaxType::Uuid,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_SSID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_SSID,
    name: Attribute::DomainSsid,
    description: "The domains site-wide SSID for device autoconfiguration of wireless".to_string(),
    indexed: true,
    unique: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DENIED_NAME_DL10: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DENIED_NAME,
    name: Attribute::DeniedName,
    description: "Iname values that are not allowed to be used in 'name'.".to_string(),
    syntax: SyntaxType::Utf8StringIname,
    multivalue: true,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_TOKEN_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_TOKEN_KEY,
    name: Attribute::DomainTokenKey,
    description: "The domain token encryption private key (NOT USED)".to_string(),
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR,
    name: Attribute::FernetPrivateKeyStr,
    description: "The token encryption private key".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_GIDNUMBER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_GIDNUMBER,
    name: Attribute::GidNumber,
    description: "The groupid (uid) number of a group or account.to_string(). This is the same value as the UID number on posix accounts for security reasons".to_string(),
    indexed: true,
    unique: true,
    sync_allowed: true,
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_BADLIST_PASSWORD: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_BADLIST_PASSWORD,
    name: Attribute::BadlistPassword,
    description: "A password that is badlisted meaning that it can not be set as a valid password by any user account".to_string(),
    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_AUTH_SESSION_EXPIRY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_AUTH_SESSION_EXPIRY,
    name: Attribute::AuthSessionExpiry,
    description: "An expiration time for an authentication session".to_string(),
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_AUTH_PRIVILEGE_EXPIRY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_AUTH_PRIVILEGE_EXPIRY,
    name: Attribute::PrivilegeExpiry,
    description: "An expiration time for a privileged authentication session".to_string(),
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_AUTH_PASSWORD_MINIMUM_LENGTH: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_AUTH_PASSWORD_MINIMUM_LENGTH,
    name: Attribute::AuthPasswordMinimumLength,
    description: "Minimum length of passwords".to_string(),
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LOGINSHELL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LOGINSHELL,
    name: Attribute::LoginShell,
    description: "A POSIX user's UNIX login shell".to_string(),
    sync_allowed: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_UNIX_PASSWORD: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_UNIX_PASSWORD,
    name: Attribute::UnixPassword,
    description: "A POSIX user's UNIX login password".to_string(),
    indexed: true,
    syntax: SyntaxType::Credential,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_NSUNIQUEID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_NSUNIQUEID,
    name: Attribute::NsUniqueId,
    description: "A unique id compatibility for 389-ds/dsee".to_string(),
    indexed: true,
    unique: true,
    sync_allowed: true,
    syntax: SyntaxType::NsUniqueId,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ACCOUNT_EXPIRE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_EXPIRE,
    name: Attribute::AccountExpire,
    description: "The datetime after which this account no longer may authenticate".to_string(),
    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ACCOUNT_VALID_FROM: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_VALID_FROM,
    name: Attribute::AccountValidFrom,
    description: "The datetime after which this account may commence authenticating".to_string(),
    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_WEBAUTHN_ATTESTATION_CA_LIST: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_WEBAUTHN_ATTESTATION_CA_LIST,
    name: Attribute::WebauthnAttestationCaList,
    description: "A set of CA's that limit devices that can be used with webauthn".to_string(),
    syntax: SyntaxType::WebauthnAttestationCaList,
    multivalue: true,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_NAME,
    name: Attribute::OAuth2RsName,
    description: "The unique name of an external Oauth2 resource".to_string(),
    indexed: true,
    unique: true,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN,
    name: Attribute::OAuth2RsOrigin,
    description: "The origin domain of an OAuth2 client".to_string(),
    syntax: SyntaxType::Url,
    multivalue: true,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING,
    name: Attribute::OAuth2RsOriginLanding,
    description: "The landing page of an RS, that will automatically trigger the auth process".to_string(),
    syntax: SyntaxType::Url,
    ..Default::default()
};

// Introduced in DomainLevel4
pub static ref SCHEMA_ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT_DL4: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT,
    name: Attribute::OAuth2AllowLocalhostRedirect,
    description: "Allow public clients associated to this RS to redirect to localhost".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_CLAIM_MAP_DL4: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_CLAIM_MAP,
    name: Attribute::OAuth2RsClaimMap,
    description: "A set of custom claims mapped to group memberships of accounts".to_string(),
    indexed: true,
    multivalue: true,
    // CHANGE ME
    syntax: SyntaxType::OauthClaimMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP,
    name: Attribute::OAuth2RsScopeMap,
    description: "A reference to a group mapped to scopes for the associated oauth2 resource server".to_string(),
    indexed: true,
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
    name: Attribute::OAuth2RsSupScopeMap,
    description: "A reference to a group mapped to scopes for the associated oauth2 resource server".to_string(),
    indexed: true,
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET,
    name: Attribute::OAuth2RsBasicSecret,
    description: "When using oauth2 basic authentication, the secret string of the resource server".to_string(),
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY,
    name: Attribute::OAuth2RsTokenKey,
    description: "An oauth2 resource servers unique token signing key".to_string(),
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
    name: Attribute::OAuth2RsImplicitScopes,
    description: "An oauth2 resource servers scopes that are implicitly granted to all users".to_string(),
    multivalue: true,
    syntax: SyntaxType::OauthScope,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP,
    name: Attribute::OAuth2ConsentScopeMap,
    description: "A set of scopes mapped from a relying server to a user, where the user has previously consented to the following. If changed or deleted, consent will be re-sought".to_string(),
    indexed: true,
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_STRICT_REDIRECT_URI_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_STRICT_REDIRECT_URI,
    name: Attribute::OAuth2StrictRedirectUri,
    description: "Represents if strict redirect uri enforcement is enabled.".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};


pub static ref SCHEMA_ATTR_OAUTH2_DEVICE_FLOW_ENABLE_DL9: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_DEVICE_FLOW_ENABLE,
    name: Attribute::OAuth2DeviceFlowEnable,
    description: "Represents if OAuth2 Device Flow is permitted on this client.".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ES256_PRIVATE_KEY_DER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ES256_PRIVATE_KEY_DER,
    name: Attribute::Es256PrivateKeyDer,
    description: "An es256 private key".to_string(),
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_RS256_PRIVATE_KEY_DER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_RS256_PRIVATE_KEY_DER,
    name: Attribute::Rs256PrivateKeyDer,
    description: "An rs256 private key".to_string(),
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY,
    name: Attribute::JwsEs256PrivateKey,
    description: "An es256 private key for jws".to_string(),
    indexed: true,
    unique: true,
    syntax: SyntaxType::JwsKeyEs256,
    ..Default::default()
};

// TO BE REMOVED IN A FUTURE RELEASE
pub static ref SCHEMA_ATTR_PRIVATE_COOKIE_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PRIVATE_COOKIE_KEY,
    name: Attribute::PrivateCookieKey,
    description: "An private cookie hmac key".to_string(),
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE,
    name: Attribute::OAuth2AllowInsecureClientDisablePkce,
    description: "Allows disabling of PKCE for insecure OAuth2 clients".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
    name: Attribute::OAuth2JwtLegacyCryptoEnable,
    description: "Allows enabling legacy JWT cryptograhpy for clients".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
    name: Attribute::CredentialUpdateIntentToken,
    description: "The status of a credential update intent token".to_string(),
    indexed: true,
    multivalue: true,
    syntax: SyntaxType::IntentToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PASSKEYS: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PASSKEYS,
    name: Attribute::PassKeys,
    description: "A set of registered passkeys".to_string(),
    indexed: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::Passkey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ATTESTED_PASSKEYS: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ATTESTED_PASSKEYS,
    name: Attribute::AttestedPasskeys,
    description: "A set of registered device keys".to_string(),
    indexed: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::AttestedPasskey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DYNGROUP_FILTER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DYNGROUP_FILTER,
    name: Attribute::DynGroupFilter,
    description: "A filter describing the set of entries to add to a dynamic group".to_string(),
    syntax: SyntaxType::JsonFilter,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME,
    name: Attribute::OAuth2PreferShortUsername,
    description: "Use 'name' instead of 'spn' in the preferred_username claim".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_API_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_API_TOKEN_SESSION,
    name: Attribute::ApiTokenSession,
    description: "A session entry related to an issued API token".to_string(),
    indexed: true,
    unique: true,
    multivalue: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION,
    name: Attribute::UserAuthTokenSession,
    description: "A session entry related to an issued user auth token".to_string(),
    indexed: true,
    unique: true,
    multivalue: true,
    syntax: SyntaxType::Session,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_SESSION,
    name: Attribute::OAuth2Session,
    description: "A session entry to an active oauth2 session, bound to a parent user auth token".to_string(),
    indexed: true,
    multivalue: true,
    syntax: SyntaxType::Oauth2Session,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_TOKEN_SESSION,
    name: Attribute::SyncTokenSession,
    description: "A session entry related to an issued sync token".to_string(),
    indexed: true,
    unique: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_COOKIE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_COOKIE,
    name: Attribute::SyncCookie,
    description: "A private sync cookie for a remote IDM source".to_string(),
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_GRANT_UI_HINT: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_GRANT_UI_HINT,
    name: Attribute::GrantUiHint,
    description: "A UI hint that is granted via membership to a group".to_string(),
    indexed: true,
    multivalue: true,
    syntax: SyntaxType::UiHint,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL,
    name: Attribute::SyncCredentialPortal,
    description: "The url of an external credential portal for synced accounts to visit to update their credentials".to_string(),
    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_YIELD_AUTHORITY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_YIELD_AUTHORITY,
    name: Attribute::SyncYieldAuthority,
    description: "A set of attributes that have their authority yielded to Kanidm in a sync agreement".to_string(),
    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_CREDENTIAL_TYPE_MINIMUM: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CREDENTIAL_TYPE_MINIMUM,
    name: Attribute::CredentialTypeMinimum,
    description: "The minimum level of credential type that can satisfy this policy".to_string(),
    multivalue: false,
    syntax: SyntaxType::CredentialType,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LIMIT_SEARCH_MAX_RESULTS_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LIMIT_SEARCH_MAX_RESULTS,
    name: Attribute::LimitSearchMaxResults,
    description: "The maximum number of query results that may be returned in a single operation".to_string(),
    multivalue: false,
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LIMIT_SEARCH_MAX_FILTER_TEST_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LIMIT_SEARCH_MAX_FILTER_TEST,
    name: Attribute::LimitSearchMaxFilterTest,
    description: "The maximum number of entries that may be examined in a partially indexed query".to_string(),
    multivalue: false,
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_KEY_INTERNAL_DATA_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_KEY_INTERNAL_DATA,
    name: Attribute::KeyInternalData,
    description: "".to_string(),
    multivalue: true,
    syntax: SyntaxType::KeyInternal,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_KEY_PROVIDER_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_KEY_PROVIDER,
    name: Attribute::KeyProvider,
    description: "".to_string(),
    multivalue: false,
    indexed: true,
    syntax: SyntaxType::ReferenceUuid,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_KEY_ACTION_ROTATE_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_KEY_ACTION_ROTATE,
    name: Attribute::KeyActionRotate,
    description: "".to_string(),
    multivalue: false,
    // Ephemeral action.
    phantom: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_KEY_ACTION_REVOKE_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_KEY_ACTION_REVOKE,
    name: Attribute::KeyActionRevoke,
    description: "".to_string(),
    multivalue: true,
    // Ephemeral action.
    phantom: true,
    syntax: SyntaxType::HexString,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_ES256_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_ES256,
    name: Attribute::KeyActionImportJwsEs256,
    description: "".to_string(),
    multivalue: true,
    // Ephemeral action.
    phantom: true,
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_RS256_DL6: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_RS256,
    name: Attribute::KeyActionImportJwsRs256,
    description: "".to_string(),
    multivalue: true,
    // Ephemeral action.
    phantom: true,
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PATCH_LEVEL_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PATCH_LEVEL,
    name: Attribute::PatchLevel,
    description: "".to_string(),
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_DEVELOPMENT_TAINT_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_DEVELOPMENT_TAINT,
    name: Attribute::DomainDevelopmentTaint,
    description: "A flag to show that the domain has been run on a development build, and will need additional work to upgrade/migrate.".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_ALLOW_EASTER_EGGS_DL9: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_ALLOW_EASTER_EGGS,
    name: Attribute::DomainAllowEasterEggs,
    description: "A flag to enable easter eggs in the server that may not always be wanted by all users/deployments.".to_string(),
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_REFERS_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_REFERS,
    name: Attribute::Refers,
    description: "A reference to linked object".to_string(),
    indexed: true,
    multivalue: false,
    syntax: SyntaxType::ReferenceUuid,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LINKED_GROUP_DL8: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LINKED_GROUP,
    name: Attribute::LinkedGroup,
    description: "A reference linking a group to an entry".to_string(),
    multivalue: false,
    indexed: true,
    syntax: SyntaxType::ReferenceUuid,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ALLOW_PRIMARY_CRED_FALLBACK_DL8: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ALLOW_PRIMARY_CRED_FALLBACK,
    name: Attribute::AllowPrimaryCredFallback,
    description: "Allow fallback to primary password if no POSIX password exists".to_string(),
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_CERTIFICATE_DL7: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CERTIFICATE,
    name: Attribute::Certificate,
    description: "An x509 Certificate".to_string(),
    multivalue: false,
    syntax: SyntaxType::Certificate,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_APPLICATION_PASSWORD_DL8: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_APPLICATION_PASSWORD,
    name: Attribute::ApplicationPassword,
    description: "A set of application passwords".to_string(),
    multivalue: true,
    indexed: true,
    syntax: SyntaxType::ApplicationPassword,
    ..Default::default()
};

// === classes ===
pub static ref SCHEMA_CLASS_PERSON_DL8: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_PERSON,
    name: EntryClass::Person.into(),
    description: "Object representation of a person".to_string(),

    sync_allowed: true,
    systemmay: vec![
        Attribute::PrimaryCredential,
        Attribute::PassKeys,
        Attribute::AttestedPasskeys,
        Attribute::CredentialUpdateIntentToken,
        Attribute::SshPublicKey,
        Attribute::RadiusSecret,
        Attribute::OAuth2ConsentScopeMap,
        Attribute::UserAuthTokenSession,
        Attribute::OAuth2Session,
        Attribute::Mail,
        Attribute::LegalName,
        Attribute::ApplicationPassword,
    ],
    systemmust: vec![
        Attribute::IdVerificationEcKey
    ],
    systemexcludes: vec![EntryClass::ServiceAccount.into(), EntryClass::Application.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ORGPERSON: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ORGPERSON,
    name: EntryClass::OrgPerson.into(),
    description: "Object representation of an org person".to_string(),

    systemmay: vec![
        Attribute::LegalName
        ],
    systemmust: vec![
        Attribute::Mail,
        Attribute::DisplayName,
        Attribute::Name
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_GROUP_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_GROUP,
    name: EntryClass::Group.into(),
    description: "Object representation of a group".to_string(),

    sync_allowed: true,
    systemmay: vec![
        Attribute::Member,
        Attribute::GrantUiHint,
        Attribute::Description,
        Attribute::Mail,
    ],
    systemmust: vec![
        Attribute::Name,
        Attribute::Spn],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_DYNGROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DYNGROUP,
    name: EntryClass::DynGroup.into(),
    description: "Object representation of a dynamic group".to_string(),

    systemmust: vec![Attribute::DynGroupFilter],
    systemmay: vec![Attribute::DynMember],
    systemsupplements: vec![Attribute::Group.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ACCOUNT_POLICY_DL8: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ACCOUNT_POLICY,
    name: EntryClass::AccountPolicy.into(),
    description: "Policies applied to accounts that are members of a group".to_string(),

    systemmay: vec![
        Attribute::AuthSessionExpiry,
        Attribute::PrivilegeExpiry,
        Attribute::AuthPasswordMinimumLength,
        Attribute::CredentialTypeMinimum,
        Attribute::WebauthnAttestationCaList,
        Attribute::LimitSearchMaxResults,
        Attribute::LimitSearchMaxFilterTest,
        Attribute::AllowPrimaryCredFallback,
    ],
    systemsupplements: vec![Attribute::Group.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ACCOUNT_DL5: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ACCOUNT,
    name: EntryClass::Account.into(),
    description: "Object representation of an account".to_string(),

    sync_allowed: true,
    systemmay: vec![
        Attribute::AccountExpire,
        Attribute::AccountValidFrom,
        Attribute::NameHistory,
    ],
    systemmust: vec![
        Attribute::DisplayName,
        Attribute::Name,
        Attribute::Spn
    ],
    systemsupplements: vec![
        EntryClass::Person.into(),
        EntryClass::ServiceAccount.into(),
        EntryClass::OAuth2ResourceServer.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SERVICE_ACCOUNT_DL7: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SERVICE_ACCOUNT,
    name: EntryClass::ServiceAccount.into(),
    description: "Object representation of service account".to_string(),

    sync_allowed: true,
    systemmay: vec![
        Attribute::SshPublicKey,
        Attribute::UserAuthTokenSession,
        Attribute::OAuth2Session,
        Attribute::OAuth2ConsentScopeMap,
        Attribute::Description,

        Attribute::Mail,
        Attribute::PrimaryCredential,
        Attribute::ApiTokenSession,
    ],
    systemexcludes: vec![EntryClass::Person.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SYNC_ACCOUNT_DL7: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SYNC_ACCOUNT,
    name: EntryClass::SyncAccount.into(),
    description: "Object representation of sync account".to_string(),

    systemmust: vec![Attribute::Name],
    systemmay: vec![
        Attribute::SyncTokenSession,
        Attribute::SyncCookie,
        Attribute::SyncCredentialPortal,
        Attribute::SyncYieldAuthority,
    ],
    systemexcludes: vec![EntryClass::Account.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_DOMAIN_INFO_DL10: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DOMAIN_INFO,
    name: EntryClass::DomainInfo.into(),
    description: "Local domain information and configuration".to_string(),

    systemmay: vec![
        Attribute::DomainSsid,
        Attribute::DomainLdapBasedn,
        Attribute::LdapMaxQueryableAttrs,
        Attribute::LdapAllowUnixPwBind,
        Attribute::Image,
        Attribute::PatchLevel,
        Attribute::DomainDevelopmentTaint,
        Attribute::DomainAllowEasterEggs,
        Attribute::DomainDisplayName,
    ],
    systemmust: vec![
        Attribute::Name,
        Attribute::DomainUuid,
        Attribute::DomainName,
        Attribute::Version,
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_POSIXGROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_POSIXGROUP,
    name: EntryClass::PosixGroup.into(),
    description: "Object representation of a posix group, requires group".to_string(),

    sync_allowed: true,
    systemmust: vec![Attribute::GidNumber],
    systemsupplements: vec![Attribute::Group.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_POSIXACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_POSIXACCOUNT,
    name: EntryClass::PosixAccount.into(),
    description: "Object representation of a posix account, requires account".to_string(),

    sync_allowed: true,
    systemmay: vec![Attribute::LoginShell, Attribute::UnixPassword],
    systemmust: vec![Attribute::GidNumber],
    systemsupplements: vec![Attribute::Account.into()],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SYSTEM_CONFIG: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SYSTEM_CONFIG,
    name: EntryClass::SystemConfig.into(),
    description: "The class representing a system (topologies) configuration options".to_string(),

    systemmay: vec![
        Attribute::Description,
        Attribute::BadlistPassword,
        Attribute::AuthSessionExpiry,
        Attribute::PrivilegeExpiry,
        Attribute::DeniedName
        ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_OAUTH2_RS_DL9: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS,
    name: EntryClass::OAuth2ResourceServer.into(),
    description: "The class epresenting a configured OAuth2 Client".to_string(),

    systemmay: vec![
        Attribute::Description,
        Attribute::OAuth2RsScopeMap,
        Attribute::OAuth2RsSupScopeMap,
        Attribute::OAuth2JwtLegacyCryptoEnable,
        Attribute::OAuth2PreferShortUsername,
        Attribute::Image,
        Attribute::OAuth2RsClaimMap,
        Attribute::OAuth2Session,
        Attribute::OAuth2RsOrigin,
        Attribute::OAuth2StrictRedirectUri,
        Attribute::OAuth2DeviceFlowEnable,
        // Deprecated
        Attribute::Rs256PrivateKeyDer,
        Attribute::OAuth2RsTokenKey,
        Attribute::Es256PrivateKeyDer,
    ],
    systemmust: vec![
        Attribute::OAuth2RsOriginLanding,
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_OAUTH2_RS_BASIC_DL5: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_BASIC,
    name: EntryClass::OAuth2ResourceServerBasic.into(),
    description: "The class representing a configured OAuth2 client authenticated with HTTP basic authentication".to_string(),

    systemmay: vec![
        Attribute::OAuth2AllowInsecureClientDisablePkce,
    ],
    systemmust: vec![ Attribute::OAuth2RsBasicSecret],
    systemexcludes: vec![ EntryClass::OAuth2ResourceServerPublic.into()],
    ..Default::default()
};

// Introduced in DomainLevel4
pub static ref SCHEMA_CLASS_OAUTH2_RS_PUBLIC_DL4: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_PUBLIC,
    name: EntryClass::OAuth2ResourceServerPublic.into(),
    description: "The class representing a configured Public OAuth2 Client with PKCE verification".to_string(),

    systemmay: vec![Attribute::OAuth2AllowLocalhostRedirect],
    systemexcludes: vec![EntryClass::OAuth2ResourceServerBasic.into()],
    ..Default::default()
};

// =========================================
// KeyProviders

pub static ref SCHEMA_CLASS_KEY_PROVIDER_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_PROVIDER,
    name: EntryClass::KeyProvider.into(),
    description: "A provider for cryptographic key storage and operations".to_string(),
    systemmay: vec![
        Attribute::Description,
    ],
    systemmust: vec![
        Attribute::Name,
    ],
    systemsupplements: vec![
        EntryClass::KeyProviderInternal.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_KEY_PROVIDER_INTERNAL_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_PROVIDER_INTERNAL,
    name: EntryClass::KeyProviderInternal.into(),
    description: "The Kanidm internal cryptographic key provider".to_string(),
    ..Default::default()
};

// =========================================
// KeyObjects

pub static ref SCHEMA_CLASS_KEY_OBJECT_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_OBJECT,
    name: EntryClass::KeyObject.into(),
    description: "A cryptographic key object that can be used by a provider".to_string(),
    systemmust: vec![
        Attribute::KeyProvider,
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_KEY_OBJECT_JWT_ES256_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_OBJECT_JWT_ES256,
    name: EntryClass::KeyObjectJwtEs256.into(),
    description: "A marker class indicating that this keyobject must provide jwt es256 capability.".to_string(),
    systemsupplements: vec![
        EntryClass::KeyObject.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_KEY_OBJECT_JWT_RS256: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_OBJECT_JWT_RS256,
    name: EntryClass::KeyObjectJwtRs256.into(),
    description: "A marker class indicating that this keyobject must provide jwt rs256 capability.".to_string(),
    systemsupplements: vec![
        EntryClass::KeyObject.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_KEY_OBJECT_JWE_A128GCM_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_OBJECT_JWE_A128GCM,
    name: EntryClass::KeyObjectJweA128GCM.into(),
    description: "A marker class indicating that this keyobject must provide jwe aes-256-gcm capability.".to_string(),
    systemsupplements: vec![
        EntryClass::KeyObject.into(),
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_KEY_OBJECT_INTERNAL_DL6: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_KEY_OBJECT_INTERNAL,
    name: EntryClass::KeyObjectInternal.into(),
    description: "A cryptographic key object that can be used by the internal provider".to_string(),
    systemmay: vec![
        Attribute::KeyInternalData,
    ],
    systemsupplements: vec![
        EntryClass::KeyObject.into(),
    ],
    ..Default::default()
};

// =========================================

pub static ref SCHEMA_CLASS_CLIENT_CERTIFICATE_DL7: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_CLIENT_CERTIFICATE,
    name: EntryClass::ClientCertificate.into(),
    description: "A client authentication certificate".to_string(),
    systemmay: vec![],
    systemmust: vec![
        Attribute::Certificate,
        Attribute::Refers,
    ],
    ..Default::default()
};

pub static ref SCHEMA_CLASS_APPLICATION_DL8: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_APPLICATION,
    name: EntryClass::Application.into(),

    description: "The class representing an application".to_string(),
    systemmust: vec![Attribute::Name, Attribute::LinkedGroup],
    systemmay: vec![Attribute::Description],
    systemsupplements: vec![EntryClass::ServiceAccount.into()],
    ..Default::default()
};

);
