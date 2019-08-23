use uuid::Uuid;

// On test builds, define to 60 seconds
#[cfg(test)]
pub static PURGE_TIMEOUT: u64 = 60;
// For production, 1 hour.
#[cfg(not(test))]
pub static PURGE_TIMEOUT: u64 = 3600;

pub static STR_UUID_ADMIN: &'static str = "00000000-0000-0000-0000-000000000000";
pub static STR_UUID_ANONYMOUS: &'static str = "00000000-0000-0000-0000-ffffffffffff";
pub static STR_UUID_DOES_NOT_EXIST: &'static str = "00000000-0000-0000-0000-fffffffffffe";
lazy_static! {
    pub static ref UUID_ADMIN: Uuid = Uuid::parse_str(STR_UUID_ADMIN).unwrap();
    pub static ref UUID_DOES_NOT_EXIST: Uuid =
        Uuid::parse_str(STR_UUID_DOES_NOT_EXIST).unwrap();
    pub static ref UUID_ANONYMOUS: Uuid = Uuid::parse_str(STR_UUID_ANONYMOUS).unwrap();
}

pub static JSON_ADMIN_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-000000000000"
    },
    "state": null,
    "attrs": {
        "class": ["account", "object"],
        "name": ["admin"],
        "uuid": ["00000000-0000-0000-0000-000000000000"],
        "description": ["Builtin Admin account."],
        "displayname": ["Administrator"]
    }
}"#;

pub static _UUID_IDM_ADMINS: &'static str = "00000000-0000-0000-0000-000000000001";
pub static JSON_IDM_ADMINS_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-000000000001"
    },
    "state": null,
    "attrs": {
        "class": ["group", "object"],
        "name": ["idm_admins"],
        "uuid": ["00000000-0000-0000-0000-000000000001"],
        "description": ["Builtin IDM Administrators Group."],
        "member": ["00000000-0000-0000-0000-000000000000"]
    }
}"#;

pub static _UUID_SYSTEM_INFO: &'static str = "00000000-0000-0000-0000-ffffff000001";
pub static JSON_SYSTEM_INFO_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-ffffff000001"
    },
    "state": null,
    "attrs": {
        "class": ["object", "system_info"],
        "uuid": ["00000000-0000-0000-0000-ffffff000001"],
        "description": ["System info and metadata object."],
        "version": ["1"],
        "domain": ["example.com"]
    }
}"#;

pub static _UUID_IDM_ADMINS_ACP_SEARCH_V1: &'static str = "00000000-0000-0000-0000-ffffff000002";
pub static JSON_IDM_ADMINS_ACP_SEARCH_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-ffffff000002"
    },
    "state": null,
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_admins_acp_search"],
        "uuid": ["00000000-0000-0000-0000-ffffff000002"],
        "description": ["Builtin IDM Administrators Access Controls."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000001\"]}"
        ],
        "acp_targetscope": [
            "{\"Pres\":\"class\"}"
        ],
        "acp_search_attr": ["name", "class", "uuid"]
    }
}"#;

pub static _UUID_IDM_ADMINS_ACP_REVIVE_V1: &'static str = "00000000-0000-0000-0000-ffffff000003";
pub static JSON_IDM_ADMINS_ACP_REVIVE_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-ffffff000003"
    },
    "state": null,
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_modify"],
        "name": ["idm_admins_acp_revive"],
        "uuid": ["00000000-0000-0000-0000-ffffff000003"],
        "description": ["Builtin IDM Administrators Access Controls."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "{\"Eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000001\"]}"
        ],
        "acp_targetscope": [
            "{\"Eq\":[\"class\",\"recycled\"]}"
        ],
        "acp_modify_removedattr": ["class"],
        "acp_modify_class": ["recycled"]
    }
}"#;

pub static _UUID_IDM_SELF_ACP_READ_V1: &'static str = "00000000-0000-0000-0000-ffffff000004";
pub static JSON_IDM_SELF_ACP_READ_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-ffffff000004"
    },
    "state": null,
    "attrs": {
        "class": ["object", "access_control_profile", "access_control_search"],
        "name": ["idm_self_acp_read"],
        "uuid": ["00000000-0000-0000-0000-ffffff000004"],
        "description": ["Builtin IDM Control for self read - required for whoami."],
        "acp_enable": ["true"],
        "acp_receiver": [
            "\"Self\""
        ],
        "acp_targetscope": [
            "\"Self\""
        ],
        "acp_search_attr": ["name", "uuid"]
    }
}"#;

pub static JSON_ANONYMOUS_V1: &'static str = r#"{
    "valid": {
        "uuid": "00000000-0000-0000-0000-ffffffffffff"
    },
    "state": null,
    "attrs": {
        "class": ["account", "object"],
        "name": ["anonymous"],
        "uuid": ["00000000-0000-0000-0000-ffffffffffff"],
        "description": ["Anonymous access account."],
        "displayname": ["Anonymous"]
    }
}"#;

// Core
// Schema uuids start at 00000000-0000-0000-0000-ffff00000000
pub static UUID_SCHEMA_ATTR_CLASS: &'static str = "00000000-0000-0000-0000-ffff00000000";
pub static UUID_SCHEMA_ATTR_UUID: &'static str = "00000000-0000-0000-0000-ffff00000001";
pub static UUID_SCHEMA_ATTR_NAME: &'static str = "00000000-0000-0000-0000-ffff00000002";
pub static UUID_SCHEMA_ATTR_PRINCIPAL_NAME: &'static str = "00000000-0000-0000-0000-ffff00000003";
pub static UUID_SCHEMA_ATTR_DESCRIPTION: &'static str = "00000000-0000-0000-0000-ffff00000004";
pub static UUID_SCHEMA_ATTR_MULTIVALUE: &'static str = "00000000-0000-0000-0000-ffff00000005";
pub static UUID_SCHEMA_ATTR_INDEX: &'static str = "00000000-0000-0000-0000-ffff00000006";
pub static UUID_SCHEMA_ATTR_SYNTAX: &'static str = "00000000-0000-0000-0000-ffff00000007";
pub static UUID_SCHEMA_ATTR_SYSTEMMAY: &'static str = "00000000-0000-0000-0000-ffff00000008";
pub static UUID_SCHEMA_ATTR_MAY: &'static str = "00000000-0000-0000-0000-ffff00000009";
pub static UUID_SCHEMA_ATTR_SYSTEMMUST: &'static str = "00000000-0000-0000-0000-ffff00000010";
pub static UUID_SCHEMA_ATTR_MUST: &'static str = "00000000-0000-0000-0000-ffff00000011";
pub static UUID_SCHEMA_ATTR_MEMBEROF: &'static str = "00000000-0000-0000-0000-ffff00000012";
pub static UUID_SCHEMA_ATTR_MEMBER: &'static str = "00000000-0000-0000-0000-ffff00000013";
pub static UUID_SCHEMA_ATTR_DIRECTMEMBEROF: &'static str = "00000000-0000-0000-0000-ffff00000014";
pub static UUID_SCHEMA_ATTR_VERSION: &'static str = "00000000-0000-0000-0000-ffff00000015";
pub static UUID_SCHEMA_ATTR_DOMAIN: &'static str = "00000000-0000-0000-0000-ffff00000016";
pub static UUID_SCHEMA_ATTR_ACP_ENABLE: &'static str = "00000000-0000-0000-0000-ffff00000017";
pub static UUID_SCHEMA_ATTR_ACP_RECEIVER: &'static str = "00000000-0000-0000-0000-ffff00000018";
pub static UUID_SCHEMA_ATTR_ACP_TARGETSCOPE: &'static str = "00000000-0000-0000-0000-ffff00000019";
pub static UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR: &'static str = "00000000-0000-0000-0000-ffff00000020";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_CLASS: &'static str = "00000000-0000-0000-0000-ffff00000021";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_ATTR: &'static str = "00000000-0000-0000-0000-ffff00000022";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR: &'static str =
    "00000000-0000-0000-0000-ffff00000023";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR: &'static str =
    "00000000-0000-0000-0000-ffff00000024";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS: &'static str = "00000000-0000-0000-0000-ffff00000025";

pub static UUID_SCHEMA_CLASS_ATTRIBUTETYPE: &'static str = "00000000-0000-0000-0000-ffff00000026";
pub static UUID_SCHEMA_CLASS_CLASSTYPE: &'static str = "00000000-0000-0000-0000-ffff00000027";
pub static UUID_SCHEMA_CLASS_OBJECT: &'static str = "00000000-0000-0000-0000-ffff00000028";
pub static UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT: &'static str =
    "00000000-0000-0000-0000-ffff00000029";
pub static UUID_SCHEMA_CLASS_MEMBEROF: &'static str = "00000000-0000-0000-0000-ffff00000030";

pub static UUID_SCHEMA_CLASS_RECYCLED: &'static str = "00000000-0000-0000-0000-ffff00000031";
pub static UUID_SCHEMA_CLASS_TOMBSTONE: &'static str = "00000000-0000-0000-0000-ffff00000032";
pub static UUID_SCHEMA_CLASS_SYSTEM_INFO: &'static str = "00000000-0000-0000-0000-ffff00000033";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE: &'static str =
    "00000000-0000-0000-0000-ffff00000034";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH: &'static str =
    "00000000-0000-0000-0000-ffff00000035";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE: &'static str =
    "00000000-0000-0000-0000-ffff00000036";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY: &'static str =
    "00000000-0000-0000-0000-ffff00000037";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE: &'static str =
    "00000000-0000-0000-0000-ffff00000038";
pub static UUID_SCHEMA_CLASS_SYSTEM: &'static str = "00000000-0000-0000-0000-ffff00000039";

// system supplementary
pub static UUID_SCHEMA_ATTR_DISPLAYNAME: &'static str = "00000000-0000-0000-0000-ffff00000040";
pub static JSON_SCHEMA_ATTR_DISPLAYNAME: &'static str = r#"{
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000040"
    },
    "state": null,
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
      "multivalue": [
        "false"
      ],
      "name": [
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
pub static UUID_SCHEMA_ATTR_MAIL: &'static str = "00000000-0000-0000-0000-ffff00000041";
pub static JSON_SCHEMA_ATTR_MAIL: &'static str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000041"
    },
    "state": null,
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
      "multivalue": [
        "true"
      ],
      "name": [
        "mail"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000041"
      ]
    }
  }
"#;
pub static UUID_SCHEMA_ATTR_SSH_PUBLICKEY: &'static str = "00000000-0000-0000-0000-ffff00000042";
pub static JSON_SCHEMA_ATTR_SSH_PUBLICKEY: &'static str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000042"
    },
    "state": null,
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
      "multivalue": [
        "true"
      ],
      "name": [
        "ssh_publickey"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000042"
      ]
    }
  }
"#;
pub static UUID_SCHEMA_ATTR_PASSWORD: &'static str = "00000000-0000-0000-0000-ffff00000043";
pub static JSON_SCHEMA_ATTR_PASSWORD: &'static str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000043"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "attributetype"
      ],
      "description": [
        "password hash material of the object for authentication"
      ],
      "index": [],
      "multivalue": [
        "true"
      ],
      "name": [
        "password"
      ],
      "syntax": [
        "UTF8STRING"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000043"
      ]
    }
  }
"#;

pub static UUID_SCHEMA_CLASS_PERSON: &'static str = "00000000-0000-0000-0000-ffff00000044";
pub static JSON_SCHEMA_CLASS_PERSON: &'static str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000044"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a person"
      ],
      "name": [
        "person"
      ],
      "systemmay": [
        "mail",
        "memberof"
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

pub static UUID_SCHEMA_CLASS_GROUP: &'static str = "00000000-0000-0000-0000-ffff00000045";
pub static JSON_SCHEMA_CLASS_GROUP: &'static str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000045"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a group"
      ],
      "name": [
        "group"
      ],
      "systemmay": [
        "member"
      ],
      "systemmust": [
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000045"
      ]
    }
  }
"#;
pub static UUID_SCHEMA_CLASS_ACCOUNT: &'static str = "00000000-0000-0000-0000-ffff00000046";
pub static JSON_SCHEMA_CLASS_ACCOUNT: &'static str = r#"
  {
    "valid": {
      "uuid": "00000000-0000-0000-0000-ffff00000046"
    },
    "state": null,
    "attrs": {
      "class": [
        "object",
        "system",
        "classtype"
      ],
      "description": [
        "Object representation of a person"
      ],
      "name": [
        "account"
      ],
      "systemmay": [
        "password",
        "ssh_publickey"
      ],
      "systemmust": [
        "displayname",
        "name"
      ],
      "uuid": [
        "00000000-0000-0000-0000-ffff00000046"
      ]
    }
  }
"#;

// ============ TEST DATA ============
#[cfg(test)]
pub static JSON_TESTPERSON1: &'static str = r#"{
    "valid": null,
    "state": null,
    "attrs": {
        "class": ["object"],
        "name": ["testperson1"],
        "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"]
    }
}"#;

#[cfg(test)]
pub static JSON_TESTPERSON2: &'static str = r#"{
    "valid": null,
    "state": null,
    "attrs": {
        "class": ["object"],
        "name": ["testperson2"],
        "uuid": ["538faac7-4d29-473b-a59d-23023ac19955"]
    }
}"#;
