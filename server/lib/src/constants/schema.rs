//! Core Constants
//!
//! Schema uuids start at `00000000-0000-0000-0000-ffff00000000`
//!
use crate::constants::uuids::*;
use crate::constants::values::*;
use crate::entry::EntryInitNew;
use crate::value::IndexType;
use crate::value::{SyntaxType, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema {
    pub attrs: SchemaAttrs,
}
impl From<Schema> for EntryInitNew {
    fn from(value: Schema) -> Self {
        value.attrs.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SchemaAttrs {
    pub classname: Option<&'static str>,
    pub attributename: Option<&'static str>,
    pub class: Vec<Value>,
    pub description: &'static str,
    pub index: Vec<IndexType>,
    pub unique: bool,
    pub multivalue: bool,
    pub sync_allowed: bool,
    pub syntax: SyntaxType,
    pub uuid: uuid::Uuid,
    pub systemmay: Vec<&'static str>,
    pub systemexcludes: Vec<&'static str>,
    pub systemmust: Vec<&'static str>,
    pub systemsupplements: Vec<&'static str>,
}

impl From<SchemaAttrs> for Schema {
    fn from(attrs: SchemaAttrs) -> Self {
        assert!(!attrs.class.is_empty());
        Self { attrs }
    }
}
impl From<SchemaAttrs> for EntryInitNew {
    fn from(value: SchemaAttrs) -> Self {
        let mut entry = EntryInitNew::new();

        if value.class.contains(&CLASS_CLASSTYPE.clone()) {
            #[allow(clippy::expect_used)]
            entry.set_ava(
                "classname",
                vec![Value::new_iutf8(
                    value.classname.expect("This requires a class name!"),
                )]
                .into_iter(),
            );
        } else if value.class.contains(&CLASS_ATTRIBUTETYPE.clone()) {
            #[allow(clippy::expect_used)]
            entry.set_ava(
                "attributename",
                vec![Value::new_iutf8(
                    value
                        .attributename
                        .expect("This requires an attribute name!"),
                )]
                .into_iter(),
            );
            entry.add_ava("multivalue", Value::Bool(value.multivalue));
            // syntax
            entry.set_ava("syntax", vec![Value::Syntax(value.syntax)]);
            entry.set_ava("unique", vec![Value::Bool(value.unique)].into_iter());
            // index
            entry.set_ava("index", value.index.into_iter().map(Value::Index));
        }

        // class
        entry.set_ava("class", value.class);
        // description
        entry.set_ava(
            "description",
            vec![Value::new_utf8s(value.description)].into_iter(),
        );
        // unique
        // multivalue

        // sync_allowed
        entry.set_ava(
            "sync_allowed",
            vec![Value::Bool(value.sync_allowed)].into_iter(),
        );

        // uid
        entry.set_ava("uuid", vec![Value::Uuid(value.uuid)].into_iter());

        // systemmay
        if !value.systemmay.is_empty() {
            entry.set_ava(
                "systemmay",
                value.systemmay.into_iter().map(Value::new_iutf8),
            );
        }
        // systemexcludes
        if !value.systemexcludes.is_empty() {
            entry.set_ava(
                "systemexcludes",
                value.systemexcludes.into_iter().map(Value::new_iutf8),
            );
        }
        // systemmust
        if !value.systemmust.is_empty() {
            entry.set_ava(
                "systemmust",
                value.systemmust.into_iter().map(Value::new_iutf8),
            );
        }
        // systemsupplements
        if !value.systemsupplements.is_empty() {
            entry.set_ava(
                "systemsupplements",
                value.systemsupplements.into_iter().map(Value::new_iutf8),
            );
        }

        entry
    }
}

lazy_static!(

pub static ref SCHEMA_ATTR_DISPLAYNAME: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "The publicly visible display name of this person",
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    attributename: Some("displayname"),
    syntax: SyntaxType::Utf8String,
    uuid: UUID_SCHEMA_ATTR_DISPLAYNAME,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_MAIL: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_MAIL,
    attributename: Some("mail"),
    description: "mail addresses of the object",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::EmailAddress,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_SSH_PUBLICKEY: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "SSH public keys of the object",
    index: vec![],
    unique: false,
    multivalue: true,
    sync_allowed: true,
    attributename: Some("ssh_publickey"),
    syntax: SyntaxType::SshKey,
    uuid: UUID_SCHEMA_ATTR_SSH_PUBLICKEY,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_PRIMARY_CREDENTIAL: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "Primary credential material of the account for authentication interactively.",
    index: vec![IndexType::Presence],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    attributename: Some("primary_credential"),
    syntax: SyntaxType::Credential,
    uuid: UUID_SCHEMA_ATTR_PRIMARY_CREDENTIAL,
    ..Default::default()
});
pub static ref SCHEMA_ATTR_LEGALNAME: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "The private and sensitive legal name of this person",
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    attributename: Some("legalname"),
    syntax: SyntaxType::Utf8String,
    uuid: UUID_SCHEMA_ATTR_LEGALNAME,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_NAME_HISTORY: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "The history of names that a person has had",
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    sync_allowed: true,
    attributename: Some("name_history"),
    syntax: SyntaxType::AuditLogString,
    uuid: UUID_SCHEMA_ATTR_NAME_HISTORY,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_RADIUS_SECRET: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "The accounts generated radius secret for device network authentication",
    index: vec![],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    attributename: Some("radius_secret"),
    syntax: SyntaxType::SecretUtf8String,
    uuid: UUID_SCHEMA_ATTR_RADIUS_SECRET,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DOMAIN_NAME: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_NAME,
    attributename: Some("domain_name"),
    description: "The domain's DNS name for webauthn and SPN generation purposes.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality, IndexType::Presence],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DOMAIN_LDAP_BASEDN: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_LDAP_BASEDN,
    attributename: Some("domain_ldap_basedn"),
    description:
        "The domain's optional ldap basedn. If unset defaults to domain components of domain name.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DOMAIN_DISPLAY_NAME: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_DISPLAY_NAME,
    attributename: Some("domain_display_name"),
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "The user-facing display name of the Kanidm domain.",
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DOMAIN_UUID: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_UUID,
    attributename: Some("domain_uuid"),
    description: "The domain's uuid, used in CSN and trust relationships.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::Uuid,
    ..Default::default()
});
pub static ref SCHEMA_ATTR_DOMAIN_SSID: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_SSID,
    attributename: Some("domain_ssid"),
    description: "The domains site-wide SSID for device autoconfiguration of wireless",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::Utf8String,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DOMAIN_TOKEN_KEY: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DOMAIN_TOKEN_KEY,
    attributename: Some("domain_token_key"),
    description: "The domain token encryption private key (NOT USED).",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR,
    attributename: Some("fernet_private_key_str"),
    description: "The token encryption private key.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_GIDNUMBER: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_GIDNUMBER,
    attributename: Some("gidnumber"),
    description: "The groupid (uid) number of a group or account. This is the same value as the UID number on posix accounts for security reasons.",

    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    sync_allowed: true,
    syntax: SyntaxType::Uint32,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_BADLIST_PASSWORD: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_BADLIST_PASSWORD,
    attributename: Some("badlist_password"),
    description: "A password that is badlisted meaning that it can not be set as a valid password by any user account.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_LOGINSHELL: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_LOGINSHELL,
    attributename: Some("loginshell"),
    description: "A POSIX user's UNIX login shell",

    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_UNIX_PASSWORD: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_UNIX_PASSWORD,
    attributename: Some("unix_password"),
    description: "A POSIX user's UNIX login password.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Presence],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Credential,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_NSUNIQUEID: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_NSUNIQUEID,
    attributename: Some("nsuniqueid"),
    description: "A unique id compatibility for 389-ds/dsee",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    sync_allowed: true,
    syntax: SyntaxType::NsUniqueId,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_ACCOUNT_EXPIRE: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_EXPIRE,
    attributename: Some("account_expire"),
    description: "The datetime after which this accounnt no longer may authenticate.",

    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_ACCOUNT_VALID_FROM: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_ACCOUNT_VALID_FROM,
    attributename: Some("account_valid_from"),
    description: "The datetime after which this account may commence authenticating.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    sync_allowed: true,
    syntax: SyntaxType::DateTime,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_NAME: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_NAME,
    attributename: Some("oauth2_rs_name"),
    description: "The unique name of an external Oauth2 resource",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::Utf8StringIname,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN,
    attributename: Some("oauth2_rs_origin"),
    description: "The origin domain of an oauth2 resource server",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Url,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING,
    attributename: Some("oauth2_rs_origin_landing"),
    description: "The landing page of an RS, that will automatically trigger the auth process.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Url,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP,
    attributename: Some("oauth2_rs_scope_map"),
    description:
        "A reference to a group mapped to scopes for the associated oauth2 resource server",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
    attributename: Some("oauth2_rs_sup_scope_map"),
    description:
        "A reference to a group mapped to scopes for the associated oauth2 resource server",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET,
    attributename: Some("oauth2_rs_basic_secret"),
    description: "When using oauth2 basic authentication, the secret string of the resource server",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY,
    attributename: Some("oauth2_rs_token_key"),
    description: "An oauth2 resource servers unique token signing key",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::SecretUtf8String,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
    attributename: Some("oauth2_rs_implicit_scopes"),
    description: "An oauth2 resource servers scopes that are implicitly granted to all users",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::OauthScope,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP,
    attributename: Some("oauth2_consent_scope_map"),
    description: "A set of scopes mapped from a relying server to a user, where the user has previously consented to the following. If changed or deleted, consent will be re-sought.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
        ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::OauthScopeMap,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_ES256_PRIVATE_KEY_DER: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_ES256_PRIVATE_KEY_DER,
    attributename: Some("es256_private_key_der"),
    description: "An es256 private key",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_RS256_PRIVATE_KEY_DER: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_RS256_PRIVATE_KEY_DER,
    attributename: Some("rs256_private_key_der"),
    description: "An rs256 private key",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY,
    attributename: Some("jws_es256_private_key"),
    description: "An es256 private key for jws",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::JwsKeyEs256,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_PRIVATE_COOKIE_KEY: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_PRIVATE_COOKIE_KEY,
    attributename: Some("private_cookie_key"),
    description: "An private cookie hmac key",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE: Schema =
Schema::from(SchemaAttrs {
        uuid: UUID_SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE,
        attributename: Some("oauth2_allow_insecure_client_disable_pkce"),
        description: "Allows disabling of PKCE for insecure OAuth2 clients",
        class: vec![
            CLASS_OBJECT.clone(),
            CLASS_SYSTEM.clone(),
            CLASS_ATTRIBUTETYPE.clone(),
        ],
        index: vec![],
        unique: false,
        multivalue: false,
        syntax: SyntaxType::Boolean,
        ..Default::default()
    });

pub static ref SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
    attributename: Some("oauth2_jwt_legacy_crypto_enable"),
    description: "Allows enabling legacy JWT cryptograhpy for clients",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
    attributename: Some("credential_update_intent_token"),
    description: "The status of a credential update intent token",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::IntentToken,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_PASSKEYS: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_PASSKEYS,
    attributename: Some("passkeys"),
    description: "A set of registered passkeys",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::Passkey,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DEVICEKEYS: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DEVICEKEYS,
    attributename: Some("devicekeys"),
    description: "A set of registered device keys",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    sync_allowed: true,
    syntax: SyntaxType::DeviceKey,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_DYNGROUP_FILTER: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_DYNGROUP_FILTER,
    attributename: Some("dyngroup_filter"),
    description: "A filter describing the set of entries to add to a dynamic group",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::JsonFilter,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME,
    attributename: Some("oauth2_prefer_short_username"),
    description: "Use 'name' instead of 'spn' in the preferred_username claim",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Boolean,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_API_TOKEN_SESSION: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_API_TOKEN_SESSION,
    attributename: Some("api_token_session"),
    description: "A session entry related to an issued API token",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    description: "A session entry related to an issued user auth token",
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: true,
    attributename: Some("user_auth_token_session"),
    syntax: SyntaxType::Session,
    uuid: UUID_SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_OAUTH2_SESSION: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_OAUTH2_SESSION,
    attributename: Some("oauth2_session"),
    description: "A session entry to an active oauth2 session, bound to a parent user auth token",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::Oauth2Session,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_SYNC_TOKEN_SESSION: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_SYNC_TOKEN_SESSION,
    attributename: Some("sync_token_session"),
    description: "A session entry related to an issued sync token",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: true,
    multivalue: false,
    syntax: SyntaxType::ApiToken,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_SYNC_COOKIE: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_SYNC_COOKIE,
    attributename: Some("sync_cookie"),
    description: "A private sync cookie for a remote IDM source",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::PrivateBinary,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_GRANT_UI_HINT: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_GRANT_UI_HINT,
    attributename: Some("grant_ui_hint"),
    description: "A UI hint that is granted via membership to a group",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    index: vec![IndexType::Equality],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::UiHint,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL,
    attributename: Some("sync_credential_portal"),
    description: "The url of an external credential portal for synced accounts to visit to update their credentials.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    unique: false,
    multivalue: false,
    syntax: SyntaxType::Url,
    ..Default::default()
});

pub static ref SCHEMA_ATTR_SYNC_YIELD_AUTHORITY: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_ATTR_SYNC_YIELD_AUTHORITY,
    attributename: Some("sync_yield_authority"),
    description: "A set of attributes that have their authority yielded to Kanidm in a sync agreement.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_ATTRIBUTETYPE.clone(),
    ],
    unique: false,
    multivalue: true,
    syntax: SyntaxType::Utf8StringInsensitive,
    ..Default::default()
});

// === classes ===

pub static ref SCHEMA_CLASS_PERSON: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_PERSON,
    classname: Some("person"),
    description: "Object representation of a person",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    sync_allowed: true,
    systemmay: vec!["mail", "legalname"],
    systemmust: vec!["displayname", "name"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_ORGPERSON: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    description: "Object representation of an org person",
    classname: Some("orgperson"),
    systemmay: vec!["legalname"],
    systemmust: vec!["mail", "displayname", "name"],
    uuid: UUID_SCHEMA_CLASS_ORGPERSON,
    ..Default::default()
});

pub static ref SCHEMA_CLASS_GROUP: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_GROUP,
    classname: Some("group"),
    description: "Object representation of a group",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    sync_allowed: true,
    systemmay: vec!["member", "grant_ui_hint", "description"],
    systemmust: vec!["name", "spn"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_DYNGROUP: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_DYNGROUP,
    classname: Some("dyngroup"),
    description: "Object representation of a dynamic group",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    systemmust: vec!["dyngroup_filter"],
    systemmay: vec!["dynmember"],
    systemsupplements: vec!["group"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_ACCOUNT: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_ACCOUNT,
    classname: Some("account"),
    description: "Object representation of an account",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],

    sync_allowed: true,
    systemmay: vec![
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
    ],
    systemmust: vec!["displayname", "name", "spn"],
    systemsupplements: vec!["person", "service_account"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_SERVICE_ACCOUNT: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_SERVICE_ACCOUNT,
    classname: Some("service_account"),
    description: "Object representation of service account",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    sync_allowed: true,
    systemmay: vec![
        "mail",
        "primary_credential",
        "jws_es256_private_key",
        "api_token_session",
    ],
    systemexcludes: vec!["person"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_SYNC_ACCOUNT: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_SYNC_ACCOUNT,
    classname: Some("sync_account"),
    description: "Object representation of sync account",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    systemmust: vec!["name", "jws_es256_private_key"],
    systemmay: vec![
        "sync_token_session",
        "sync_cookie",
        "sync_credential_portal",
        "sync_yield_authority",
    ],
    systemexcludes: vec!["account"],
    ..Default::default()
});

// domain_info type
//  domain_uuid
//  domain_name <- should be the dns name?
//  domain_ssid <- for radius
//
pub static ref SCHEMA_CLASS_DOMAIN_INFO: Schema = Schema::from(SchemaAttrs {
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    uuid: UUID_SCHEMA_CLASS_DOMAIN_INFO,
    classname: Some("domain_info"),
    description: "Local domain information and partial configuration.",
    systemmay: vec!["domain_ssid", "domain_ldap_basedn"],
    systemmust: vec![
        "name",
        "domain_uuid",
        "domain_name",
        "domain_display_name",
        "fernet_private_key_str",
        "es256_private_key_der",
        "private_cookie_key",
        "version",
    ],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_POSIXGROUP: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_POSIXGROUP,
    classname: Some("posixgroup"),
    description: "Object representation of a posix group, requires group",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    sync_allowed: true,
    systemmust: vec!["gidnumber"],
    systemsupplements: vec!["group"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_POSIXACCOUNT: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_POSIXACCOUNT,
    classname: Some("posixaccount"),
    description: "Object representation of a posix account, requires account",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    sync_allowed: true,
    systemmay: vec!["loginshell", "unix_password"],
    systemmust: vec!["gidnumber"],
    systemsupplements: vec!["account"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_SYSTEM_CONFIG: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_SYSTEM_CONFIG,
    classname: Some("system_config"),
    description: "The class representing a system (topologies) configuration options.",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    systemmay: vec!["description", "badlist_password"],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_OAUTH2_RS: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS,
    classname: Some("oauth2_resource_server"),
    description: "The class representing a configured Oauth2 Resource Server",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    systemmay: vec![
        "description",
        "oauth2_rs_scope_map",
        "oauth2_rs_sup_scope_map",
        "rs256_private_key_der",
        "oauth2_jwt_legacy_crypto_enable",
        "oauth2_prefer_short_username",
        "oauth2_rs_origin_landing",
    ],
    systemmust: vec![
        "oauth2_rs_name",
        "displayname",
        "oauth2_rs_origin",
        "oauth2_rs_token_key",
        "es256_private_key_der",
    ],
    ..Default::default()
});

pub static ref SCHEMA_CLASS_OAUTH2_RS_BASIC: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_BASIC,
    classname: Some("oauth2_resource_server_basic"),
    description: "The class representing a configured Oauth2 Resource Server authenticated with http basic authentication",
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    systemmay: vec![ "oauth2_allow_insecure_client_disable_pkce"],
    systemmust: vec![ "oauth2_rs_basic_secret"],
    systemexcludes: vec![ "oauth2_resource_server_public"],
    ..Default::default()
});


pub static ref SCHEMA_CLASS_OAUTH2_RS_PUBLIC: Schema = Schema::from(SchemaAttrs {
    uuid: UUID_SCHEMA_CLASS_OAUTH2_RS_PUBLIC,
    classname: Some("oauth2_resource_server_public"),
    class: vec![
        CLASS_OBJECT.clone(),
        CLASS_SYSTEM.clone(),
        CLASS_CLASSTYPE.clone(),
    ],
    description: "The class representing a configured Oauth2 Resource Server with public clients and pkce verification",
    systemexcludes: vec!["oauth2_resource_server_basic"],
    ..Default::default()
});

);
