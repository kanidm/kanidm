//! Core Constants
//!
//! Schema uuids start at `00000000-0000-0000-0000-ffff00000000`
//!
use crate::constants::uuids::*;
use crate::schema::{SchemaAttribute, SchemaClass};
use crate::value::IndexType;
use crate::value::SyntaxType;
use smartstring::alias::String as AttrString;

/// this turns a vector of &str into a vector of AttrString
macro_rules! attrstring_vec {
    ($input:expr) => {
        $input
            .into_iter()
            .map(|s| AttrString::from(s))
            .collect::<Vec<AttrString>>()
    };
}

lazy_static!(

pub static ref SCHEMA_ATTR_DISPLAYNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DISPLAYNAME,
    name: AttrString::from("displayname"),
    description: "The publicly visible display name of this person".to_string(),

    index: vec![IndexType::Equality],
    sync_allowed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_MAIL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_MAIL,
    name: AttrString::from("mail"),
    description: "mail addresses of the object".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::EmailAddress,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SSH_PUBLICKEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SSH_PUBLICKEY,
    name: AttrString::from("ssh_publickey"),
    description: "SSH public keys of the object".to_string(),

    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::SshKey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PRIMARY_CREDENTIAL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PRIMARY_CREDENTIAL,
    name: AttrString::from("primary_credential"),
    description: "Primary credential material of the account for authentication interactively.to_string().".to_string(),

    index: vec![IndexType::Presence],
    sync_allowed: true,
    syntax: SyntaxType::Credential,
    ..Default::default()
};
pub static ref SCHEMA_ATTR_LEGALNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LEGALNAME,
    name: AttrString::from("legalname"),
    description: "The private and sensitive legal name of this person".to_string(),

    index: vec![IndexType::Equality],
    sync_allowed: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_NAME_HISTORY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_NAME_HISTORY,
    name: AttrString::from("name_history"),
    description: "The history of names that a person has had".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::AuditLogString,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_RADIUS_SECRET: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_RADIUS_SECRET,
    name: AttrString::from("radius_secret"),
    description: "The accounts generated radius secret for device network authentication".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_NAME,
    name: AttrString::from("domain_name"),
    description: "The domain's DNS name for webauthn and SPN generation purposes.to_string().".to_string(),

    index: vec![IndexType::Equality, IndexType::Presence],
    unique: true,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_LDAP_BASEDN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_LDAP_BASEDN,
    name: AttrString::from("domain_ldap_basedn"),
    description:
        "The domain's optional ldap basedn. If unset defaults to domain components of domain name.".to_string(),

    unique: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_DISPLAY_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_DISPLAY_NAME,
    name: AttrString::from("domain_display_name"),
    description: "The user-facing display name of the Kanidm domain.to_string().".to_string(),

    index: vec![IndexType::Equality],
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_UUID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_UUID,
    name: AttrString::from("domain_uuid"),
    description: "The domain's uuid, used in CSN and trust relationships.to_string().".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::Uuid,
    ..Default::default()
};
pub static ref SCHEMA_ATTR_DOMAIN_SSID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_SSID,
    name: AttrString::from("domain_ssid"),
    description: "The domains site-wide SSID for device autoconfiguration of wireless".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DOMAIN_TOKEN_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_TOKEN_KEY,
    name: AttrString::from("domain_token_key"),
    description: "The domain token encryption private key (NOT USED).to_string().".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR,
    name: AttrString::from("fernet_private_key_str"),
    description: "The token encryption private key.to_string().".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_GIDNUMBER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_GIDNUMBER,
    name: AttrString::from("gidnumber"),
    description: "The groupid (uid) number of a group or account.to_string(). This is the same value as the UID number on posix accounts for security reasons.".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    sync_allowed: true,
    syntax: SyntaxType::Uint32,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_BADLIST_PASSWORD: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_BADLIST_PASSWORD,
    name: AttrString::from("badlist_password"),
    description: "A password that is badlisted meaning that it can not be set as a valid password by any user account.to_string().".to_string(),

    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_LOGINSHELL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_LOGINSHELL,
    name: AttrString::from("loginshell"),
    description: "A POSIX user's UNIX login shell".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_UNIX_PASSWORD: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_UNIX_PASSWORD,
    name: AttrString::from("unix_password"),
    description: "A POSIX user's UNIX login password.to_string().".to_string(),

    index: vec![IndexType::Presence],
    syntax: SyntaxType::Credential,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_NSUNIQUEID: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_NSUNIQUEID,
    name: AttrString::from("nsuniqueid"),
    description: "A unique id compatibility for 389-ds/dsee".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    sync_allowed: true,
    syntax: SyntaxType::NsUniqueId,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ACCOUNT_EXPIRE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_EXPIRE,
    name: AttrString::from("account_expire"),
    description: "The datetime after which this accounnt no longer may authenticate.to_string().".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ACCOUNT_VALID_FROM: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_VALID_FROM,
    name: AttrString::from("account_valid_from"),
    description: "The datetime after which this account may commence authenticating.to_string().".to_string(),

    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_NAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_NAME,
    name: AttrString::from("oauth2_rs_name"),
    description: "The unique name of an external Oauth2 resource".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN,
    name: AttrString::from("oauth2_rs_origin"),
    description: "The origin domain of an oauth2 resource server".to_string(),

    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING,
    name: AttrString::from("oauth2_rs_origin_landing"),
    description: "The landing page of an RS, that will automatically trigger the auth process.to_string().".to_string(),

    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP,
    name: AttrString::from("oauth2_rs_scope_map"),
    description:
        "A reference to a group mapped to scopes for the associated oauth2 resource server".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
    name: AttrString::from("oauth2_rs_sup_scope_map"),
    description:
        "A reference to a group mapped to scopes for the associated oauth2 resource server".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET,
    name: AttrString::from("oauth2_rs_basic_secret"),
    description: "When using oauth2 basic authentication, the secret string of the resource server".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY,
    name: AttrString::from("oauth2_rs_token_key"),
    description: "An oauth2 resource servers unique token signing key".to_string(),

    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
    name: AttrString::from("oauth2_rs_implicit_scopes"),
    description: "An oauth2 resource servers scopes that are implicitly granted to all users".to_string(),

    multivalue: true,
    syntax: SyntaxType::OauthScope,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP,
    name: AttrString::from("oauth2_consent_scope_map"),
    description: "A set of scopes mapped from a relying server to a user, where the user has previously consented to the following. If changed or deleted, consent will be re-sought.".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_ES256_PRIVATE_KEY_DER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_ES256_PRIVATE_KEY_DER,
    name: AttrString::from("es256_private_key_der"),
    description: "An es256 private key".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_RS256_PRIVATE_KEY_DER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_RS256_PRIVATE_KEY_DER,
    name: AttrString::from("rs256_private_key_der"),
    description: "An rs256 private key".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY,
    name: AttrString::from("jws_es256_private_key"),
    description: "An es256 private key for jws".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::JwsKeyEs256,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PRIVATE_COOKIE_KEY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PRIVATE_COOKIE_KEY,
    name: AttrString::from("private_cookie_key"),
    description: "An private cookie hmac key".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE,
    name: AttrString::from("oauth2_allow_insecure_client_disable_pkce"),
    description: "Allows disabling of PKCE for insecure OAuth2 clients".to_string(),

    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
    name: AttrString::from("oauth2_jwt_legacy_crypto_enable"),
    description: "Allows enabling legacy JWT cryptograhpy for clients".to_string(),

    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
    name: AttrString::from("credential_update_intent_token"),
    description: "The status of a credential update intent token".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::IntentToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_PASSKEYS: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_PASSKEYS,
    name: AttrString::from("passkeys"),
    description: "A set of registered passkeys".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::Passkey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DEVICEKEYS: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DEVICEKEYS,
    name: AttrString::from("devicekeys"),
    description: "A set of registered device keys".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::DeviceKey,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_DYNGROUP_FILTER: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_DYNGROUP_FILTER,
    name: AttrString::from("dyngroup_filter"),
    description: "A filter describing the set of entries to add to a dynamic group".to_string(),

    syntax: SyntaxType::JsonFilter,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME,
    name: AttrString::from("oauth2_prefer_short_username"),
    description: "Use 'name' instead of 'spn' in the preferred_username claim".to_string(),

    syntax: SyntaxType::Boolean,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_API_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_API_TOKEN_SESSION,
    name: AttrString::from("api_token_session"),
    description: "A session entry related to an issued API token".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION,
    name: AttrString::from("user_auth_token_session"),
    description: "A session entry related to an issued user auth token".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    syntax: SyntaxType::Session,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_OAUTH2_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_SESSION,
    name: AttrString::from("oauth2_session"),
    description: "A session entry to an active oauth2 session, bound to a parent user auth token".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::Oauth2Session,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_TOKEN_SESSION: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_TOKEN_SESSION,
    name: AttrString::from("sync_token_session"),
    description: "A session entry related to an issued sync token".to_string(),

    index: vec![IndexType::Equality],
    unique: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_COOKIE: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_COOKIE,
    name: AttrString::from("sync_cookie"),
    description: "A private sync cookie for a remote IDM source".to_string(),

    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_GRANT_UI_HINT: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_GRANT_UI_HINT,
    name: AttrString::from("grant_ui_hint"),
    description: "A UI hint that is granted via membership to a group".to_string(),

    index: vec![IndexType::Equality],
    multivalue: true,
    syntax: SyntaxType::UiHint,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL,
    name: AttrString::from("sync_credential_portal"),
    description: "The url of an external credential portal for synced accounts to visit to update their credentials.to_string().".to_string(),

    syntax: SyntaxType::Url,
    ..Default::default()
};

pub static ref SCHEMA_ATTR_SYNC_YIELD_AUTHORITY: SchemaAttribute = SchemaAttribute {
    uuid: UUID_SCHEMA_ATTR_SYNC_YIELD_AUTHORITY,
    name: AttrString::from("sync_yield_authority"),
    description: "A set of attributes that have their authority yielded to Kanidm in a sync agreement.to_string().".to_string(),

    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
};

// === classes ===

pub static ref SCHEMA_CLASS_PERSON: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_PERSON,
    name: AttrString::from("person"),
    description: "Object representation of a person".to_string(),

    sync_allowed: true,
    systemmay: attrstring_vec!(["mail", "legalname"]),
    systemmust: attrstring_vec!(["displayname", "name"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ORGPERSON: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ORGPERSON,
    name: AttrString::from("orgperson"),
    description: "Object representation of an org person".to_string(),

    systemmay: attrstring_vec!(["legalname"]),
    systemmust: attrstring_vec!(["mail", "displayname", "name"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_GROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_GROUP,
    name: AttrString::from("group"),
    description: "Object representation of a group".to_string(),

    sync_allowed: true,
    systemmay: attrstring_vec!(["member", "grant_ui_hint", "description"]),
    systemmust: attrstring_vec!(["name", "spn"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_DYNGROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DYNGROUP,
    name: AttrString::from("dyngroup"),
    description: "Object representation of a dynamic group".to_string(),

    systemmust: attrstring_vec!(["dyngroup_filter"]),
    systemmay: attrstring_vec!(["dynmember"]),
    systemsupplements: attrstring_vec!(["group"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_ACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_ACCOUNT,
    name: AttrString::from("account"),
    description: "Object representation of an account".to_string(),

    sync_allowed: true,
    systemmay: attrstring_vec!([
        "primary_credential",
        "passkeys",
        "devicekeys",
        "credential_update_intent_token",
        "ssh_publickey",
        "radius_secret",
        "account_expire",
        "account_valid_from",
        "mail",
        "oauth2_consent_scope_map",
        "user_auth_token_session",
        "oauth2_session",
        "description",
        "name_history",
    ]),
    systemmust: attrstring_vec!(["displayname", "name", "spn"]),
    systemsupplements: attrstring_vec!(["person", "service_account"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SERVICE_ACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SERVICE_ACCOUNT,
    name: AttrString::from("service_account"),
    description: "Object representation of service account".to_string(),

    sync_allowed: true,
    systemmay: attrstring_vec!([
        "mail",
        "primary_credential",
        "jws_es256_private_key",
        "api_token_session",
    ]),
    systemexcludes: attrstring_vec!(["person"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SYNC_ACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SYNC_ACCOUNT,
    name: AttrString::from("sync_account"),
    description: "Object representation of sync account".to_string(),

    systemmust: attrstring_vec!(["name", "jws_es256_private_key"]),
    systemmay: attrstring_vec!([
        "sync_token_session",
        "sync_cookie",
        "sync_credential_portal",
        "sync_yield_authority",
    ]),
    systemexcludes: attrstring_vec!(["account"]),
    ..Default::default()
};

// domain_info type
//  domain_uuid
//  domain_name <- should be the dns name?
//  domain_ssid <- for radius
//
pub static ref SCHEMA_CLASS_DOMAIN_INFO: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_DOMAIN_INFO,
    name: AttrString::from("domain_info"),
    description: "Local domain information and partial configuration.to_string().".to_string(),

    systemmay: attrstring_vec!(["domain_ssid", "domain_ldap_basedn"]),
    systemmust: attrstring_vec!([
        "name",
        "domain_uuid",
        "domain_name",
        "domain_display_name",
        "fernet_private_key_str",
        "es256_private_key_der",
        "private_cookie_key",
        "version",
    ]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_POSIXGROUP: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_POSIXGROUP,
    name: AttrString::from("posixgroup"),
    description: "Object representation of a posix group, requires group".to_string(),

    sync_allowed: true,
    systemmust: attrstring_vec!(["gidnumber"]),
    systemsupplements: attrstring_vec!(["group"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_POSIXACCOUNT: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_POSIXACCOUNT,
    name: AttrString::from("posixaccount"),
    description: "Object representation of a posix account, requires account".to_string(),

    sync_allowed: true,
    systemmay: attrstring_vec!(["loginshell", "unix_password"]),
    systemmust: attrstring_vec!(["gidnumber"]),
    systemsupplements: attrstring_vec!(["account"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_SYSTEM_CONFIG: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_SYSTEM_CONFIG,
    name: AttrString::from("system_config"),
    description: "The class representing a system (topologies) configuration options.to_string().".to_string(),

    systemmay: attrstring_vec!(["description", "badlist_password"]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_OAUTH2_RS: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS,
    name: AttrString::from("oauth2_resource_server"),
    description: "The class representing a configured Oauth2 Resource Server".to_string(),

    systemmay: attrstring_vec!([
        "description",
        "oauth2_rs_scope_map",
        "oauth2_rs_sup_scope_map",
        "rs256_private_key_der",
        "oauth2_jwt_legacy_crypto_enable",
        "oauth2_prefer_short_username",
        "oauth2_rs_origin_landing",
    ]),
    systemmust: attrstring_vec!([
        "oauth2_rs_name",
        "displayname",
        "oauth2_rs_origin",
        "oauth2_rs_token_key",
        "es256_private_key_der",
    ]),
    ..Default::default()
};

pub static ref SCHEMA_CLASS_OAUTH2_RS_BASIC: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_BASIC,
    name: AttrString::from("oauth2_resource_server_basic"),
    description: "The class representing a configured Oauth2 Resource Server authenticated with http basic authentication".to_string(),

    systemmay: attrstring_vec!([ "oauth2_allow_insecure_client_disable_pkce"]),
    systemmust: attrstring_vec!([ "oauth2_rs_basic_secret"]),
    systemexcludes: attrstring_vec!([ "oauth2_resource_server_public"]),
    ..Default::default()
};


pub static ref SCHEMA_CLASS_OAUTH2_RS_PUBLIC: SchemaClass = SchemaClass {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_PUBLIC,
    name: AttrString::from("oauth2_resource_server_public"),

    description: "The class representing a configured Oauth2 Resource Server with public clients and pkce verification".to_string(),
    systemexcludes: attrstring_vec!(["oauth2_resource_server_basic"]),
    ..Default::default()
};

);
