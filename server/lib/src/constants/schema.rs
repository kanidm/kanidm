// Core
// Schema uuids start at 00000000-0000-0000-0000-ffff00000000

// system supplementary
pub const JSON_SCHEMA_ATTR_DISPLAYNAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The publicly visible display name of this person"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "displayname"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000040"
      ]
    }
}"#;
pub const JSON_SCHEMA_ATTR_MAIL: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "mail addresses of the object"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "true"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "mail"
      ],
      "syntax": [
        "EMAIL_ADDRESS"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000041"
      ]
    }
  }
"#;
pub const JSON_SCHEMA_ATTR_SSH_PUBLICKEY: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "SSH public keys of the object"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "ssh_publickey"
      ],
      "syntax": [
        "SSHKEY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000042"
      ]
    }
  }
"#;
pub const JSON_SCHEMA_ATTR_PRIMARY_CREDENTIAL: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "Primary credential material of the account for authentication interactively."
      ],
      "index": [
        "PRESENCE"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "primary_credential"
      ],
      "syntax": [
        "CREDENTIAL"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000043"
      ]
    }
  }
"#;
pub const JSON_SCHEMA_ATTR_LEGALNAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The private and sensitive legal name of this person"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "legalname"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000050"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_NAME_HISTORY: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The history of names that a person has had"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "name_history"
      ],
      "syntax": [
        "AUDIT_LOG_STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000133"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_RADIUS_SECRET: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The accounts generated radius secret for device network authentication"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "radius_secret"
      ],
      "syntax": [
        "SECRET_UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000051"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_DOMAIN_NAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domain's DNS name for webauthn and SPN generation purposes."
      ],
      "index": [
        "EQUALITY",
        "PRESENCE"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_name"
      ],
      "syntax": [
        "UTF8STRING_INAME"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000053"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_DOMAIN_LDAP_BASEDN: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domain's optional ldap basedn. If unset defaults to domain components of domain name."
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_ldap_basedn"
      ],
      "syntax": [
        "UTF8STRING_INSENSITIVE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000131"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_DOMAIN_DISPLAY_NAME: &str = r#"{
  "attrs": {
    "class": [
      "object",
      "system",
      "attributetype"
    ],
    "description": [
      "The user-facing display name of the Kanidm domain."
    ],
    "index": [
      "EQUALITY"
    ],
    "unique": [
      "false"
    ],
    "multivalue": [
      "false"
    ],
    "attributename": [
      "domain_display_name"
    ],
    "syntax": [
      "UTF8STRING"
    ],
    "uuid": [
      "00000000-0000-0000-0000-ffff00000098"
    ]
  }
}"#;

pub const JSON_SCHEMA_ATTR_DOMAIN_UUID: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domain's uuid, used in CSN and trust relationships."
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_uuid"
      ],
      "syntax": [
        "UUID"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000054"
      ]
    }
}"#;
pub const JSON_SCHEMA_ATTR_DOMAIN_SSID: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domains site-wide SSID for device autoconfiguration of wireless"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_ssid"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000055"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_DOMAIN_TOKEN_KEY: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The domain token encryption private key (NOT USED)."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "domain_token_key"
      ],
      "syntax": [
        "SECRET_UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000088"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The token encryption private key."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "fernet_private_key_str"
      ],
      "syntax": [
        "SECRET_UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000095"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_GIDNUMBER: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The groupid (uid) number of a group or account. This is the same value as the UID number on posix accounts for security reasons."
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "gidnumber"
      ],
      "syntax": [
        "UINT32"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000056"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_BADLIST_PASSWORD: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A password that is badlisted meaning that it can not be set as a valid password by any user account."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "badlist_password"
      ],
      "syntax": [
        "UTF8STRING_INSENSITIVE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000059"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_LOGINSHELL: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A posix users unix login shell"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "loginshell"
      ],
      "syntax": [
        "UTF8STRING_INSENSITIVE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000061"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_UNIX_PASSWORD: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A posix users unix login password."
      ],
      "index": [
        "PRESENCE"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "unix_password"
      ],
      "syntax": [
        "CREDENTIAL"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000062"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_NSUNIQUEID: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A unique id compatibility for 389-ds/dsee"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "nsuniqueid"
      ],
      "syntax": [
        "NSUNIQUEID"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000067"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_ACCOUNT_EXPIRE: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The datetime after which this accounnt no longer may authenticate."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "account_expire"
      ],
      "syntax": [
        "DATETIME"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000072"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_ACCOUNT_VALID_FROM: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The datetime after which this account may commence authenticating."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "account_valid_from"
      ],
      "syntax": [
        "DATETIME"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000073"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_NAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The unique name of an external Oauth2 resource"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_rs_name"
      ],
      "syntax": [
        "UTF8STRING_INAME"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000080"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_ORIGIN: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The origin domain of an oauth2 resource server"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_rs_origin"
      ],
      "syntax": [
        "URL"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000081"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The landing page of an RS, that will automatically trigger the auth process."
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_rs_origin_landing"
      ],
      "syntax": [
        "URL"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000120"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A reference to a group mapped to scopes for the associated oauth2 resource server"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "oauth2_rs_scope_map"
      ],
      "syntax": [
        "OAUTH_SCOPE_MAP"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000082"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A reference to a group mapped to scopes for the associated oauth2 resource server"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "oauth2_rs_sup_scope_map"
      ],
      "syntax": [
        "OAUTH_SCOPE_MAP"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000112"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "When using oauth2 basic authentication, the secret string of the resource server"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_rs_basic_secret"
      ],
      "syntax": [
        "SECRET_UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000083"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "An oauth2 resource servers unique token signing key"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_rs_token_key"
      ],
      "syntax": [
        "SECRET_UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000084"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "An oauth2 resource servers scopes that are implicitly granted to all users"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "oauth2_rs_implicit_scopes"
      ],
      "syntax": [
        "OAUTH_SCOPE"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000089"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A set of scopes mapped from a relying server to a user, where the user has previously consented to the following. If changed or deleted, consent will be re-sought."
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "oauth2_consent_scope_map"
      ],
      "syntax": [
        "OAUTH_SCOPE_MAP"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000097"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_ES256_PRIVATE_KEY_DER: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "An es256 private key"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "es256_private_key_der"
      ],
      "syntax": [
        "PRIVATE_BINARY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000090"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_RS256_PRIVATE_KEY_DER: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "An rs256 private key"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "rs256_private_key_der"
      ],
      "syntax": [
        "PRIVATE_BINARY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000093"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "An es256 private key for jws"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "jws_es256_private_key"
      ],
      "syntax": [
        "JWS_KEY_ES256"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000110"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_PRIVATE_COOKIE_KEY: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "An private cookie hmac key"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "private_cookie_key"
      ],
      "syntax": [
        "PRIVATE_BINARY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000130"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "Allows disabling of pkce for insecure oauth2 clients"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_allow_insecure_client_disable_pkce"
      ],
      "syntax": [
        "BOOLEAN"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000091"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "Allows enabling legacy jwt cryptograhpy for clients"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_jwt_legacy_crypto_enable"
      ],
      "syntax": [
        "BOOLEAN"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000092"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "The status of a credential update intent token"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "credential_update_intent_token"
      ],
      "syntax": [
        "INTENT_TOKEN"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000096"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_PASSKEYS: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A set of registered passkeys"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "passkeys"
      ],
      "syntax": [
        "PASSKEY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000099"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_DEVICEKEYS: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A set of registered device keys"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "sync_allowed": [
        "true"
      ],
      "attributename": [
        "devicekeys"
      ],
      "syntax": [
        "DEVICEKEY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000100"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_DYNGROUP_FILTER: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A filter describing the set of entries to add to a dynamic group"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "dyngroup_filter"
      ],
      "syntax": [
        "JSON_FILTER"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000108"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "Use 'name' instead of 'spn' in the preferred_username claim"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "oauth2_prefer_short_username"
      ],
      "syntax": [
        "BOOLEAN"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000109"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_API_TOKEN_SESSION: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A session entry related to an issued api token"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "api_token_session"
      ],
      "syntax": [
        "APITOKEN"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000111"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A session entry related to an issued user auth token"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "user_auth_token_session"
      ],
      "syntax": [
        "SESSION"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000113"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_OAUTH2_SESSION: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A session entry to an active oauth2 session, bound to a parent user auth token"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "oauth2_session"
      ],
      "syntax": [
        "OAUTH2SESSION"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000117"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_SYNC_TOKEN_SESSION: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A session entry related to an issued sync token"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "true"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "sync_token_session"
      ],
      "syntax": [
        "APITOKEN"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000115"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_SYNC_COOKIE: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A private sync cookie for a remote IDM source"
      ],
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
      ],
      "attributename": [
        "sync_cookie"
      ],
      "syntax": [
        "PRIVATE_BINARY"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000116"
      ]
    }
}"#;

pub const JSON_SCHEMA_ATTR_GRANT_UI_HINT: &str = r#"{
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "A ui hint that is granted via membership to a group"
      ],
      "index": [
        "EQUALITY"
      ],
      "unique": [
        "false"
      ],
      "multivalue": [
        "true"
      ],
      "attributename": [
        "grant_ui_hint"
      ],
      "syntax": [
        "UIHINT"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000119"
      ]
    }
}"#;

// === classes ===

pub const JSON_SCHEMA_CLASS_PERSON: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a person"
      ],
      "sync_allowed": [
        "true"
      ],
      "classname": [
        "person"
      ],
      "systemmay": [
        "mail",
        "legalname"
      ],
      "systemmust": [
        "displayname",
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000044"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_ORGPERSON: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of an org person"
      ],
      "classname": [
        "orgperson"
      ],
      "systemmay": [
        "legalname"
      ],
      "systemmust": [
        "mail",
        "displayname",
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000094"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_GROUP: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a group"
      ],
      "sync_allowed": [
        "true"
      ],
      "classname": [
        "group"
      ],
      "systemmay": [
        "member",
        "grant_ui_hint",
        "description"
      ],
      "systemmust": [
        "name",
        "spn"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000045"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_DYNGROUP: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a dynamic group"
      ],
      "classname": [
        "dyngroup"
      ],
      "systemmust": [
        "dyngroup_filter"
      ],
      "systemmay": [
        "dynmember"
      ],
      "systemsupplements": [
        "group"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000107"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_ACCOUNT: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a account"
      ],
      "sync_allowed": [
        "true"
      ],
      "classname": [
        "account"
      ],
      "systemmay": [
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
        "name_history"
      ],
      "systemmust": [
        "displayname",
        "name",
        "spn"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000046"
      ],
      "systemsupplements": [
        "person",
        "service_account"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_SERVICE_ACCOUNT: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of service account"
      ],
      "sync_allowed": [
        "true"
      ],
      "classname": [
        "service_account"
      ],
      "systemmay": [
        "mail",
        "primary_credential",
        "jws_es256_private_key",
        "api_token_session"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000106"
      ],
      "systemexcludes": [
        "person"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_SYNC_ACCOUNT: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of sync account"
      ],
      "classname": [
        "sync_account"
      ],
      "systemmust": [
        "name",
        "jws_es256_private_key"
      ],
      "systemmay": [
        "sync_token_session",
        "sync_cookie"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000114"
      ],
      "systemexcludes": [
        "account"
      ]
    }
  }
"#;

// domain_info type
//  domain_uuid
//  domain_name <- should be the dns name?
//  domain_ssid <- for radius
//
pub const JSON_SCHEMA_CLASS_DOMAIN_INFO: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Local domain information and partial configuration."
      ],
      "classname": [
        "domain_info"
      ],
      "systemmay": [
        "domain_ssid",
        "domain_ldap_basedn"
      ],
      "systemmust": [
        "name",
        "domain_uuid",
        "domain_name",
        "domain_display_name",
        "fernet_private_key_str",
        "es256_private_key_der",
        "private_cookie_key",
        "version"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000052"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_POSIXGROUP: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a posix group, requires group"
      ],
      "sync_allowed": [
        "true"
      ],
      "classname": [
        "posixgroup"
      ],
      "systemmust": [
        "gidnumber"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000058"
      ],
      "systemsupplements": [
        "group"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_POSIXACCOUNT: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a posix account, requires account"
      ],
      "sync_allowed": [
        "true"
      ],
      "classname": [
        "posixaccount"
      ],
      "systemmay": [
        "loginshell",
        "unix_password"
      ],
      "systemmust": [
        "gidnumber"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000057"
      ],
      "systemsupplements": [
        "account"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_SYSTEM_CONFIG: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "The class representing a system (topologies) configuration options."
      ],
      "classname": [
        "system_config"
      ],
      "systemmay": [
        "description",
        "badlist_password"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000060"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_OAUTH2_RS: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "The class representing a configured Oauth2 Resource Server"
      ],
      "classname": [
        "oauth2_resource_server"
      ],
      "systemmay": [
        "description",
        "oauth2_rs_scope_map",
        "oauth2_rs_sup_scope_map",
        "oauth2_allow_insecure_client_disable_pkce",
        "rs256_private_key_der",
        "oauth2_jwt_legacy_crypto_enable",
        "oauth2_prefer_short_username",
        "oauth2_rs_origin_landing"
      ],
      "systemmust": [
        "oauth2_rs_name",
        "displayname",
        "oauth2_rs_origin",
        "oauth2_rs_token_key",
        "es256_private_key_der"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000085"
      ]
    }
  }
"#;

pub const JSON_SCHEMA_CLASS_OAUTH2_RS_BASIC: &str = r#"
  {
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "The class representing a configured Oauth2 Resource Server authenticated with http basic"
      ],
      "classname": [
        "oauth2_resource_server_basic"
      ],
      "systemmay": [],
      "systemmust": [
        "oauth2_rs_basic_secret"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000086"
      ]
    }
  }
"#;
