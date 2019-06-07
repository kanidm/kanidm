pub static PURGE_TIMEOUT: u64 = 3600;

pub static UUID_ADMIN: &'static str = "00000000-0000-0000-0000-000000000000";
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
        "version": ["1"],
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
        "version": ["1"],
        "member": ["00000000-0000-0000-0000-000000000000"]
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
        "version": ["1"],
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
        "version": ["1"],
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

pub static _UUID_ANONYMOUS: &'static str = "00000000-0000-0000-0000-ffffffffffff";
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
        "version": ["1"],
        "displayname": ["Anonymous"]
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

// Core
pub static UUID_SCHEMA_ATTR_CLASS: &'static str = "aa0f193f-3010-4783-9c9e-f97edb14d8c2";
pub static UUID_SCHEMA_ATTR_UUID: &'static str = "642a893b-fe1a-4fe1-805d-fb78e7f83ee7";
pub static UUID_SCHEMA_ATTR_NAME: &'static str = "27be9127-5ba1-4c06-bce9-7250f2c7f630";
pub static UUID_SCHEMA_ATTR_PRINCIPAL_NAME: &'static str = "64dda3ac-12cb-4000-9b30-97a92767ccab";
pub static UUID_SCHEMA_ATTR_DESCRIPTION: &'static str = "a4da35a2-c5fb-4f8f-a341-72cd39ec9eee";
pub static UUID_SCHEMA_ATTR_SYSTEM: &'static str = "ee28df1e-cf02-49ca-80b5-8310fb619377";
pub static UUID_SCHEMA_ATTR_SECRET: &'static str = "0231c61a-0a43-4987-9293-8732ed9459fa";
pub static UUID_SCHEMA_ATTR_MULTIVALUE: &'static str = "8a6a8bf3-7053-42e2-8cda-15af7a197513";
pub static UUID_SCHEMA_ATTR_INDEX: &'static str = "2c5ff455-0709-4f67-a37c-35ff7e67bfff";
pub static UUID_SCHEMA_ATTR_SYNTAX: &'static str = "85e8c2c7-3852-48dd-bfc9-d0982a50e2ef";
pub static UUID_SCHEMA_ATTR_SYSTEMMAY: &'static str = "f3842165-90ad-4465-ad71-1de63f8c98a1";
pub static UUID_SCHEMA_ATTR_MAY: &'static str = "7adb7e2d-af8f-492e-8f1c-c5d9b7c47b5f";
pub static UUID_SCHEMA_ATTR_SYSTEMMUST: &'static str = "e2e4abc4-7083-41ea-a663-43d904d949ce";
pub static UUID_SCHEMA_ATTR_MUST: &'static str = "40e88ca8-06d7-4a51-b538-1125e51c02e0";

pub static UUID_SCHEMA_CLASS_ATTRIBUTETYPE: &'static str = "ed65a356-a4d9-45a8-b4b9-5d40d9acdb7e";
pub static UUID_SCHEMA_CLASS_CLASSTYPE: &'static str = "ec1964f6-0c72-4373-954f-f3a603c5f8bb";
pub static UUID_SCHEMA_CLASS_OBJECT: &'static str = "579bb16d-1d85-4f8e-bb3b-6fc55af582fe";
pub static UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT: &'static str =
    "0fb2171d-372b-4d0d-9194-9a4d6846c324";

pub static UUID_SCHEMA_CLASS_RECYCLED: &'static str = "813bb7e3-dadf-413d-acc4-197b03d55a4f";
pub static UUID_SCHEMA_CLASS_TOMBSTONE: &'static str = "848a1224-0c3c-465f-abd0-10a32e21830e";

// system supplementary
pub static UUID_SCHEMA_ATTR_DISPLAYNAME: &'static str = "201bc966-954b-48f5-bf25-99ffed759861";
pub static UUID_SCHEMA_ATTR_MAIL: &'static str = "fae94676-720b-461b-9438-bfe8cfd7e6cd";
pub static UUID_SCHEMA_ATTR_MEMBEROF: &'static str = "2ff1abc8-2f64-4f41-9e3d-33d44616a112";
pub static UUID_SCHEMA_ATTR_SSH_PUBLICKEY: &'static str = "52f2f13f-d35c-4cca-9f43-90a12c968f72";
pub static UUID_SCHEMA_ATTR_PASSWORD: &'static str = "a5121082-be54-4624-a307-383839b0366b";
pub static UUID_SCHEMA_ATTR_MEMBER: &'static str = "cbb7cb55-1d48-4b89-8da7-8d570e755b47";
pub static UUID_SCHEMA_ATTR_DIRECTMEMBEROF: &'static str = "63f6a766-3838-48e3-bd78-0fb1152b862f";
pub static UUID_SCHEMA_ATTR_VERSION: &'static str = "896d5095-b3ae-451e-a91f-4314165b5395";
pub static UUID_SCHEMA_ATTR_DOMAIN: &'static str = "c9926716-eaaa-4c83-a1ab-1ed4372a7491";
pub static UUID_SCHEMA_ATTR_ACP_ALLOW: &'static str = "160ebaaf-5251-444c-aa41-8d1a572c147a";
pub static UUID_SCHEMA_ATTR_ACP_ENABLE: &'static str = "7346a4a6-3dae-4e48-b606-a1c0c2abeba0";
pub static UUID_SCHEMA_ATTR_ACP_RECEIVER: &'static str = "8e48d272-7818-400f-ac74-6ae05e6c79b8";
pub static UUID_SCHEMA_ATTR_ACP_TARGETSCOPE: &'static str = "424bb6f3-44a1-4af8-8f4c-782a18f9240e";
pub static UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR: &'static str = "2ad9f789-9a9b-483b-8398-4734ef7b744f";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_CLASS: &'static str = "4daeee27-7b4a-48a1-bbb7-3bc30865c1aa";
pub static UUID_SCHEMA_ATTR_ACP_CREATE_ATTR: &'static str = "cbe953bc-9999-4536-818d-0bbb6a0ab7a6";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR: &'static str =
    "67f98a76-74c4-4bf1-8baa-6e6a5b7b064d";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR: &'static str =
    "2df6a429-e060-40e1-8551-be101aff3496";
pub static UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS: &'static str = "a6f0cf6e-c748-4aa4-8c77-9f1cb89b7f4a";

pub static UUID_SCHEMA_CLASS_PERSON: &'static str = "86c4d9e8-3820-45d7-8a8c-d3c522287010";
pub static UUID_SCHEMA_CLASS_GROUP: &'static str = "c0e4e58c-1a2e-4bc3-ad56-5950ef810ea7";
pub static UUID_SCHEMA_CLASS_ACCOUNT: &'static str = "8bbff87c-1731-455e-a0e7-bf1d0908e983";
pub static UUID_SCHEMA_CLASS_SYSTEM_INFO: &'static str = "510b2a38-0577-4680-b0ad-836ca3415e6c";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE: &'static str =
    "78dd6c9a-ac61-4e53-928f-6e8b810a469b";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH: &'static str =
    "1bbf256b-51a4-4716-9db8-ec51bb207ed5";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE: &'static str =
    "48af3c4d-0ba1-48de-a2b1-194f27ac1df1";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY: &'static str =
    "fd860561-9d0a-4f12-be30-406834292d46";
pub static UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE: &'static str =
    "58c5c197-51d8-4c30-9a8e-b8a0bb0eaacd";

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
