#![deny(warnings)]
use std::collections::HashSet;

use kanidm_client::KanidmClient;
use kanidm_proto::constants::{
    APPLICATION_JSON, ATTR_ACP_RECEIVER_GROUP, ATTR_ACP_TARGET_SCOPE, ATTR_DESCRIPTION,
    ATTR_LDAP_SSH_PUBLICKEY, ATTR_NAME,
};
use kanidmd_lib::prelude::{Attribute, EntryClass};
use kanidmd_testkit::*;
use reqwest::header::CONTENT_TYPE;

// TODO: feed this off attrs
static USER_READABLE_ATTRS: [&str; 9] = [
    "name",
    "spn",
    "displayname",
    "class",
    "memberof",
    "uuid",
    "gidnumber",
    "loginshell",
    ATTR_LDAP_SSH_PUBLICKEY,
];
// TODO: feed this off attrs
static SELF_WRITEABLE_ATTRS: [&str; 7] = [
    "name",
    "displayname",
    "legalname",
    "radius_secret",
    "primary_credential",
    ATTR_LDAP_SSH_PUBLICKEY,
    "unix_password",
];
static DEFAULT_HP_GROUP_NAMES: [&str; 24] = [
    "idm_admins",
    "system_admins",
    "idm_people_manage_priv",
    "idm_people_account_password_import_priv",
    "idm_people_extend_priv",
    "idm_people_write_priv",
    "idm_people_read_priv",
    "idm_group_manage_priv",
    "idm_group_write_priv",
    "idm_account_manage_priv",
    "idm_account_write_priv",
    "idm_account_read_priv",
    "idm_radius_servers",
    "idm_hp_account_manage_priv",
    "idm_hp_account_write_priv",
    "idm_hp_account_read_priv",
    "idm_hp_account_unix_extend_priv",
    "idm_schema_manage_priv",
    "idm_hp_group_manage_priv",
    "idm_hp_group_write_priv",
    "idm_hp_group_unix_extend_priv",
    "idm_acp_manage_priv",
    "domain_admins",
    "idm_high_privilege",
];
static DEFAULT_NOT_HP_GROUP_NAMES: [&str; 2] =
    ["idm_account_unix_extend_priv", "idm_group_unix_extend_priv"];

// Users
// - Read to all self attributes (within security constraints).
// - Write to a limited set of self attributes, such as:
//     name, displayname, legalname, ssh-keys, credentials etc.
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_users(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user_with_all_attrs(&rsclient, "self_account", Some("self_group")).await;
    create_user_with_all_attrs(&rsclient, "other_account", Some("other_group")).await;

    login_account(&rsclient, "self_account").await;

    test_read_attrs(&rsclient, "self_account", &USER_READABLE_ATTRS, true).await;
    test_read_attrs(&rsclient, "other_account", &USER_READABLE_ATTRS, true).await;

    static GROUP_READABLE_ATTRS: [&str; 5] = ["class", "name", "spn", "uuid", "member"];
    test_read_attrs(&rsclient, "self_group", &GROUP_READABLE_ATTRS, true).await;
    test_read_attrs(&rsclient, "other_group", &GROUP_READABLE_ATTRS, true).await;

    static USER_SENSITIVE_ATTRS: [&str; 2] = ["legalname", "mail"];
    test_read_attrs(&rsclient, "other_account", &USER_SENSITIVE_ATTRS, false).await;

    static SELF_READABLE_ATTRS: [&str; 1] = ["radius_secret"];
    test_read_attrs(&rsclient, "self_account", &SELF_READABLE_ATTRS, true).await;
    test_read_attrs(&rsclient, "other_account", &SELF_READABLE_ATTRS, false).await;

    test_write_attrs(&rsclient, "self_account", &SELF_WRITEABLE_ATTRS, true).await;
    test_write_attrs(&rsclient, "other_account", &SELF_WRITEABLE_ATTRS, false).await;

    static NON_SELF_WRITEABLE_ATTRS: [&str; 5] = ["spn", "class", "memberof", "gidnumber", "uuid"];
    test_write_attrs(&rsclient, "self_account", &NON_SELF_WRITEABLE_ATTRS, false).await;
}

// Account Managers
// read and write to accounts, including write credentials but NOT private data (see people manager)
// ability to lock and unlock accounts, excluding high access members.
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_account_managers(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, "account_manager", "idm_account_manage_priv").await;
    create_user_with_all_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, Some("test_group")).await;

    login_account(&rsclient, "account_manager").await;

    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &USER_READABLE_ATTRS,
        true,
    )
    .await;
    static ACCOUNT_MANAGER_ATTRS: [&str; 5] = [
        "name",
        "displayname",
        "primary_credential",
        ATTR_LDAP_SSH_PUBLICKEY,
        "mail",
    ];
    test_write_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &ACCOUNT_MANAGER_ATTRS,
        true,
    )
    .await;

    static PRIVATE_DATA_ATTRS: [&str; 1] = ["legalname"];
    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PRIVATE_DATA_ATTRS,
        false,
    )
    .await;
    test_write_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PRIVATE_DATA_ATTRS,
        false,
    )
    .await;
    // TODO #59: lock and _unlock, except high access members
}

// Group Managers
// read all groups
// write group but not high access
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_group_managers(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, "group_manager", "idm_group_manage_priv").await;
    // create test user without creating new groups
    create_user(&rsclient, NOT_ADMIN_TEST_USERNAME, "idm_admins").await;

    login_account(&rsclient, "group_manager").await;

    let default_group_names: HashSet<String> =
        [&DEFAULT_HP_GROUP_NAMES[..], &DEFAULT_NOT_HP_GROUP_NAMES[..]]
            .concat()
            .iter()
            .map(ToString::to_string)
            .collect();

    let groups = rsclient.idm_group_list().await.unwrap();
    let group_names: HashSet<String> = groups
        .iter()
        .map(|entry| entry.attrs.get("name").unwrap().first().unwrap())
        .cloned()
        .collect();
    assert!(default_group_names.is_subset(&group_names));

    test_modify_group(&rsclient, &DEFAULT_HP_GROUP_NAMES, false).await;
    test_modify_group(&rsclient, &DEFAULT_NOT_HP_GROUP_NAMES, true).await;

    rsclient.idm_group_create("test_group").await.unwrap();
    rsclient
        .idm_group_add_members("test_group", &[NOT_ADMIN_TEST_USERNAME])
        .await
        .unwrap();
    assert!(is_attr_writable(&rsclient, "test_group", ATTR_DESCRIPTION)
        .await
        .unwrap());
}

// Admins
// read and write access control entries.
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_admins_access_control_entries(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    static ACP_COMMON_ATTRS: [&str; 4] = [
        ATTR_NAME,
        ATTR_DESCRIPTION,
        ATTR_ACP_RECEIVER_GROUP,
        ATTR_ACP_TARGET_SCOPE,
    ];
    static ACP_ENTRIES: [&str; 28] = [
        "idm_admins_acp_recycle_search",
        "idm_admins_acp_revive",
        "idm_self_acp_read",
        "idm_self_acp_write",
        "idm_all_acp_read",
        "idm_acp_people_read_priv",
        "idm_acp_people_write_priv",
        "idm_acp_people_manage",
        "idm_acp_people_account_password_import_priv",
        "idm_acp_people_extend_priv",
        "idm_acp_group_write_priv",
        "idm_acp_account_read_priv",
        "idm_acp_account_write_priv",
        "idm_acp_account_manage",
        "idm_acp_radius_servers",
        "idm_acp_hp_account_read_priv",
        "idm_acp_hp_account_write_priv",
        "idm_acp_hp_group_write_priv",
        "idm_acp_schema_write_attrs_priv",
        "idm_acp_acp_manage_priv",
        "idm_acp_schema_write_classes_priv",
        "idm_acp_group_manage",
        "idm_acp_hp_account_manage",
        "idm_acp_hp_group_manage",
        "idm_acp_domain_admin_priv",
        "idm_acp_system_config_priv",
        "idm_acp_account_unix_extend_priv",
        "idm_acp_group_unix_extend_priv",
    ];

    for entry in ACP_ENTRIES.iter() {
        test_read_attrs(&rsclient, entry, &ACP_COMMON_ATTRS, true).await;
        test_write_attrs(&rsclient, entry, &ACP_COMMON_ATTRS, true).await;
    }
}

// read schema entries.
// TODO #252: write schema entries
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_admins_schema_entries(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    let default_classnames: HashSet<String> = [
        EntryClass::AccessControlCreate,
        EntryClass::AccessControlDelete,
        EntryClass::AccessControlModify,
        EntryClass::AccessControlProfile,
        EntryClass::AccessControlSearch,
        EntryClass::AttributeType,
        EntryClass::ClassType,
        EntryClass::ExtensibleObject,
        EntryClass::MemberOf,
        EntryClass::Object,
        EntryClass::Recycled,
        EntryClass::System,
        EntryClass::SystemInfo,
        EntryClass::Tombstone,
        EntryClass::Person,
        EntryClass::Group,
        EntryClass::Account,
        EntryClass::DomainInfo,
        EntryClass::PosixAccount,
        EntryClass::PosixGroup,
        EntryClass::SystemConfig,
    ]
    .into_iter()
    .map(|e| e.into())
    .collect();

    let classtype_entries = rsclient.idm_schema_classtype_list().await.unwrap();
    let classnames: HashSet<String> = classtype_entries
        .iter()
        .map(|entry| {
            entry
                .attrs
                .get(Attribute::ClassName.as_ref())
                .unwrap()
                .first()
                .unwrap()
        })
        .cloned()
        .collect();
    println!("{:?}", classnames);

    assert!(default_classnames.is_subset(&classnames));

    // TODO: this could probably just iterate on the enum?
    let default_attributenames: HashSet<String> = [
        Attribute::AcpCreateAttr,
        Attribute::AcpCreateClass,
        Attribute::AcpEnable,
        Attribute::AcpModifyClass,
        Attribute::AcpModifyPresentAttr,
        Attribute::AcpModifyRemovedAttr,
        Attribute::AcpReceiverGroup,
        Attribute::AcpSearchAttr,
        Attribute::AcpTargetScope,
        Attribute::AttributeName,
        Attribute::Claim,
        Attribute::Class,
        Attribute::ClassName,
        Attribute::Description,
        Attribute::DirectMemberOf,
        Attribute::Domain,
        Attribute::Index,
        Attribute::LastModifiedCid,
        Attribute::May,
        Attribute::Member,
        Attribute::MemberOf,
        Attribute::MultiValue,
        Attribute::Must,
        Attribute::Name,
        Attribute::PasswordImport,
        Attribute::Phantom,
        Attribute::Spn,
        Attribute::Syntax,
        Attribute::SystemMay,
        Attribute::SystemMust,
        Attribute::Unique,
        Attribute::Uuid,
        Attribute::Version,
        Attribute::DisplayName,
        Attribute::LegalName,
        Attribute::Mail,
        Attribute::LdapSshPublicKey,
        Attribute::PrimaryCredential,
        Attribute::RadiusSecret,
        Attribute::DomainName,
        Attribute::DomainDisplayName,
        Attribute::DomainUuid,
        Attribute::DomainSsid,
        Attribute::GidNumber,
        Attribute::BadlistPassword,
        Attribute::AuthSessionExpiry,
        Attribute::PrivilegeExpiry,
        Attribute::LoginShell,
        Attribute::UnixPassword,
        Attribute::NsUniqueId,
    ]
    .iter()
    .map(|a| a.as_ref().to_string())
    .collect();

    let attributename_entries = rsclient.idm_schema_attributetype_list().await.unwrap();
    println!("{:?}", attributename_entries);
    let attributenames = attributename_entries
        .iter()
        .map(|entry| {
            entry
                .attrs
                .get(Attribute::AttributeName.as_ref())
                .unwrap()
                .first()
                .unwrap()
        })
        .cloned()
        .collect();

    assert!(default_attributenames.is_subset(&attributenames));
}

// modify all groups including high access groups.
// create new accounts (to bootstrap the system).
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_admins_group_entries(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, NOT_ADMIN_TEST_USERNAME, "test_group").await;

    let default_group_names =
        [&DEFAULT_HP_GROUP_NAMES[..], &DEFAULT_NOT_HP_GROUP_NAMES[..]].concat();

    test_modify_group(&rsclient, &default_group_names, true).await;
}

// modify high access accounts as an escalation for security sensitive accounts.
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_admins_ha_accounts(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    static MAIN_ATTRS: [&str; 3] = ["name", "displayname", "primary_credential"];
    test_write_attrs(&rsclient, "idm_admin", &MAIN_ATTRS, true).await;
}

// recover from the recycle bin
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_admins_recycle_accounts(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, NOT_ADMIN_TEST_USERNAME, "test_group").await;

    rsclient
        .idm_person_account_delete(NOT_ADMIN_TEST_USERNAME)
        .await
        .unwrap();
    rsclient
        .recycle_bin_revive(NOT_ADMIN_TEST_USERNAME)
        .await
        .unwrap();

    let acc = rsclient
        .idm_person_account_get(NOT_ADMIN_TEST_USERNAME)
        .await
        .unwrap();
    assert!(acc.is_some());
}

// People Managers
// read private or sensitive data of persons, IE legalName
// write private or sensitive data of persons, IE legalName
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_people_managers(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, "read_people_manager", "idm_people_read_priv").await;
    create_user_with_all_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, Some("test_group")).await;

    static PEOPLE_MANAGER_ATTRS: [&str; 2] = ["legalname", "mail"];

    static TECHNICAL_ATTRS: [&str; 3] = ["primary_credential", "radius_secret", "unix_password"];
    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PEOPLE_MANAGER_ATTRS,
        true,
    )
    .await;

    login_account(&rsclient, "read_people_manager").await;

    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PEOPLE_MANAGER_ATTRS,
        true,
    )
    .await;
    test_read_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, &TECHNICAL_ATTRS, false).await;
    test_write_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PEOPLE_MANAGER_ATTRS,
        false,
    )
    .await;
    test_write_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, &TECHNICAL_ATTRS, false).await;

    let _ = rsclient.logout();
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .unwrap();
    create_user(&rsclient, "write_people_manager", "idm_people_write_priv").await;
    login_account(&rsclient, "write_people_manager").await;

    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PEOPLE_MANAGER_ATTRS,
        true,
    )
    .await;
    test_read_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, &TECHNICAL_ATTRS, false).await;
    test_write_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &PEOPLE_MANAGER_ATTRS,
        true,
    )
    .await;
    test_write_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, &TECHNICAL_ATTRS, false).await;
}

// Anonymous Clients + Everyone Else
// read memberof, unix attrs, name, displayname, class
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_anonymous_entry(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user_with_all_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, Some("test_group")).await;
    rsclient
        .idm_group_add_members("test_group", &["anonymous"])
        .await
        .unwrap();
    add_all_attrs(&rsclient, "anonymous", "test_group", None).await;

    let _ = rsclient.logout();
    rsclient.auth_anonymous().await.unwrap();

    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &USER_READABLE_ATTRS,
        true,
    )
    .await;
    test_read_attrs(&rsclient, "anonymous", &USER_READABLE_ATTRS, true).await;
    test_write_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &SELF_WRITEABLE_ATTRS,
        false,
    )
    .await;
    test_write_attrs(&rsclient, "anonymous", &SELF_WRITEABLE_ATTRS, false).await;
}

// RADIUS Servers
// Read radius credentials
// Read other needed attributes to fulfil radius functions.
#[kanidmd_testkit::test]
async fn test_default_entries_rbac_radius_servers(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    create_user(&rsclient, "radius_server", "idm_radius_servers").await;
    create_user_with_all_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, Some("test_group")).await;

    login_account(&rsclient, "radius_server").await;
    static RADIUS_NECESSARY_ATTRS: [&str; 4] = ["name", "spn", "uuid", "radius_secret"];

    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &USER_READABLE_ATTRS,
        true,
    )
    .await;
    test_read_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &RADIUS_NECESSARY_ATTRS,
        true,
    )
    .await;
    test_write_attrs(
        &rsclient,
        NOT_ADMIN_TEST_USERNAME,
        &RADIUS_NECESSARY_ATTRS,
        false,
    )
    .await;
}

#[kanidmd_testkit::test]
async fn test_self_write_mail_priv_people(rsclient: KanidmClient) {
    login_put_admin_idm_admins(&rsclient).await;

    // test and other, each can write to themselves, but not each other
    create_user_with_all_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, None).await;
    create_user_with_all_attrs(&rsclient, "other", None).await;
    rsclient
        .idm_group_add_members(
            "idm_people_self_write_mail_priv",
            &["other", NOT_ADMIN_TEST_USERNAME],
        )
        .await
        .unwrap();
    // a non-person, they can't write to themselves even with the priv
    create_user(&rsclient, "nonperson", "nonperson_group").await;

    login_account(&rsclient, NOT_ADMIN_TEST_USERNAME).await;
    // can write to own mail
    test_write_attrs(&rsclient, NOT_ADMIN_TEST_USERNAME, &["mail"], true).await;
    // not someone elses
    test_write_attrs(&rsclient, "other", &["mail"], false).await;

    // but they can write to theirs
    login_account_via_admin(&rsclient, "other").await;
    test_write_attrs(&rsclient, "other", &["mail"], true).await;
    login_account_via_admin(&rsclient, "nonperson").await;
    test_write_attrs(&rsclient, "nonperson", &["mail"], false).await;
}

#[kanidmd_testkit::test]
async fn test_https_robots_txt(rsclient: KanidmClient) {
    // We need to do manual reqwests here.

    let response = match reqwest::get(rsclient.make_url("/robots.txt")).await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/robots.txt"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);

    eprintln!(
        "csp headers: {:#?}",
        response.headers().get("content-security-policy")
    );
    assert_ne!(response.headers().get("content-security-policy"), None);
    eprintln!("{}", response.text().await.unwrap());
}

// TODO: #1787 when the routemap comes back
// #[kanidmd_testkit::test]
// async fn test_https_routemap(rsclient: KanidmClient) {
//     // We need to do manual reqwests here.
//     let response = match reqwest::get(rsclient.make_url("/v1/routemap")).await {
//         Ok(value) => value,
//         Err(error) => {
//             panic!("Failed to query {:?} : {:#?}", addr, error);
//         }
//     };
//     eprintln!("response: {:#?}", response);
//     assert_eq!(response.status(), 200);

//     let body = response.text().await.unwrap();
//     eprintln!("{}", body);
//     assert!(body.contains("/scim/v1/Sync"));
//     assert!(body.contains(r#""path": "/v1/routemap""#));
// }

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_raw_delete(rsclient: KanidmClient) {
    // We need to do manual reqwests here.

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let post_body = serde_json::json!({"filter": "self"}).to_string();

    let response = match client
        .post(rsclient.make_url("/v1/raw/delete"))
        .header(CONTENT_TYPE, APPLICATION_JSON)
        .body(post_body)
        .send()
        .await
    {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/v1/raw/delete"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 401);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_v1_raw_logout(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = match client.get(rsclient.make_url("/v1/logout")).send().await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/v1/logout"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 401);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
}

/// This literally tests that the thing exists and responds in a way we expect, probably worth testing it better...
#[kanidmd_testkit::test]
async fn test_status_endpoint(rsclient: KanidmClient) {
    // We need to do manual reqwests here.
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = match client.get(rsclient.make_url("/status")).send().await {
        Ok(value) => value,
        Err(error) => {
            panic!(
                "Failed to query {:?} : {:#?}",
                rsclient.make_url("/status"),
                error
            );
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);

    let body = response.text().await.unwrap();
    eprintln!("{}", body);
    assert!(body.contains("true") == true);
}
