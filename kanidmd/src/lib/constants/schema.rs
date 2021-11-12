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
      "index": [],
      "unique": [
        "false"
      ],
      "multivalue": [
        "false"
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
        "The domains token signing key, which is shared between IDM servers."
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
      "index": [],
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
        "UTF8STRING"
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
        "ES256_PRIVATE_DER"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000090"
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
      "classname": [
        "group"
      ],
      "systemmay": [
        "member"
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
      "classname": [
        "account"
      ],
      "systemmay": [
        "primary_credential",
        "ssh_publickey",
        "radius_secret",
        "account_expire",
        "account_valid_from",
        "mail"
      ],
      "systemmust": [
        "displayname",
        "name",
        "spn"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000046"
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
        "domain_ssid"
      ],
      "systemmust": [
        "name",
        "domain_uuid",
        "domain_name",
        "domain_token_key"
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
      "classname": [
        "posixgroup"
      ],
      "systemmust": [
        "gidnumber"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000058"
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
        "oauth2_rs_implicit_scopes",
        "oauth2_allow_insecure_client_disable_pkce"
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
