#![deny(warnings)]
use std::collections::HashSet;

use kanidm_client::KanidmClient;
use kanidm_proto::v1::{Filter, Modify, ModifyList};

mod common;
use crate::common::{run_test, ADMIN_TEST_PASSWORD};

static USER_READABLE_ATTRS: [&str; 9] = [
    "name",
    "spn",
    "displayname",
    "class",
    "memberof",
    "uuid",
    "gidnumber",
    "loginshell",
    "ssh_publickey",
];
static SELF_WRITEABLE_ATTRS: [&str; 7] = [
    "name",
    "displayname",
    "legalname",
    "radius_secret",
    "primary_credential",
    "ssh_publickey",
    "unix_password",
];
static DEFAULT_HP_GROUP_NAMES: [&str; 22] = [
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
    "idm_schema_manage_priv",
    "idm_hp_group_manage_priv",
    "idm_hp_group_write_priv",
    "idm_acp_manage_priv",
    "domain_admins",
    "idm_high_privilege",
];
static DEFAULT_NOT_HP_GROUP_NAMES: [&str; 2] =
    ["idm_account_unix_extend_priv", "idm_group_unix_extend_priv"];

fn create_user(rsclient: &KanidmClient, id: &str, group_name: &str) -> () {
    rsclient.idm_account_create(id, "Deeeeemo").unwrap();

    // Create group and add to user to test read attr: member_of
    let _ = match rsclient.idm_group_get(&group_name).unwrap() {
        Some(_) => true,
        None => rsclient.idm_group_create(&group_name).unwrap(),
    };

    rsclient.idm_group_add_members(&group_name, &[id]).unwrap();
}

fn is_attr_writable(rsclient: &KanidmClient, id: &str, attr: &str) -> Option<bool> {
    println!("writing to attribute: {}", attr);
    match attr {
        "radius_secret" => Some(
            rsclient
                .idm_account_radius_credential_regenerate(id)
                .is_ok(),
        ),
        "primary_credential" => Some(
            rsclient
                .idm_account_primary_credential_set_password(id, "dsadjasiodqwjk12asdl")
                .is_ok(),
        ),
        "ssh_publickey" => Some(
            rsclient
                .idm_account_post_ssh_pubkey(
                    id,
                    "k1",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0\
                     L1EyR30CwoP william@amethyst",
                )
                .is_ok(),
        ),
        "unix_password" => Some(
            rsclient
                .idm_account_unix_cred_put(id, "dsadjasiodqwjk12asdl")
                .is_ok(),
        ),
        entry => {
            let new_value = match entry {
                "acp_receiver" => "{\"eq\":[\"memberof\",\"00000000-0000-0000-0000-000000000011\"]}".to_string(),
                "acp_targetscope" => "{\"and\": [{\"eq\": [\"class\",\"access_control_profile\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}".to_string(),
                 _ => id.to_string(),
            };
            let m = ModifyList::new_list(vec![
                Modify::Purged(attr.to_string()),
                Modify::Present(attr.to_string(), new_value),
            ]);
            let f = Filter::Eq("name".to_string(), id.to_string());
            Some(rsclient.modify(f.clone(), m.clone()).is_ok())
        }
    }
}

fn add_all_attrs(mut rsclient: &mut KanidmClient, id: &str, group_name: &str) {
    // Extend with posix attrs to test read attr: gidnumber and loginshell
    rsclient
        .idm_group_add_members("idm_admins", &["admin"])
        .unwrap();
    rsclient
        .idm_account_unix_extend(id, None, Some(&"/bin/bash"))
        .unwrap();
    rsclient.idm_group_unix_extend(&group_name, None).unwrap();

    // Extend with person to allow legalname
    rsclient.idm_account_person_extend(id).unwrap();

    ["ssh_publickey", "legalname", "mail"]
        .iter()
        .for_each(|attr| {
            assert!(is_attr_writable(&rsclient, id, attr).unwrap());
        });

    // Write radius credentials
    if id != "anonymous" {
        login_account(&mut rsclient, id);
        let _ = rsclient
            .idm_account_radius_credential_regenerate(id)
            .unwrap();
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
    }
}

fn create_user_with_all_attrs(
    mut rsclient: &mut KanidmClient,
    id: &str,
    optional_group: Option<&str>,
) -> () {
    let group_format = format!("{}_group", id);
    let group_name = optional_group.unwrap_or(&group_format);

    create_user(&rsclient, id, group_name);
    add_all_attrs(&mut rsclient, id, group_name);
}

fn login_account(rsclient: &mut KanidmClient, id: &str) -> () {
    rsclient
        .idm_group_add_members("idm_people_account_password_import_priv", &["admin"])
        .unwrap();
    rsclient
        .idm_group_add_members("idm_people_extend_priv", &["admin"])
        .unwrap();

    rsclient
        .idm_account_primary_credential_set_password(id, "eicieY7ahchaoCh0eeTa")
        .unwrap();

    let _ = rsclient.logout();
    let res = rsclient.auth_simple_password(id, "eicieY7ahchaoCh0eeTa");
    println!("{} logged in", id);
    assert!(res.is_ok());
}

fn test_read_attrs(rsclient: &KanidmClient, id: &str, attrs: &[&str], is_readable: bool) -> () {
    println!("Test read to {}, is readable: {}", id, is_readable);
    let rset = rsclient
        .search(Filter::Eq("name".to_string(), id.to_string()))
        .unwrap();
    let e = rset.first().unwrap();
    attrs
        .iter()
        .map(|attr| {
            println!("Reading {}", attr);
            match *attr {
                "radius_secret" => match rsclient.idm_account_radius_credential_get(id).unwrap() {
                    Some(_) => true,
                    None => false,
                },
                _ => match e.attrs.get(*attr) {
                    Some(_) => true,
                    None => false,
                },
            }
        })
        .for_each(|is_ok| assert!(is_ok == is_readable));
}

fn test_write_attrs(rsclient: &KanidmClient, id: &str, attrs: &[&str], is_writeable: bool) -> () {
    println!("Test write to {}, is writeable: {}", id, is_writeable);
    attrs
        .iter()
        .map(|attr| {
            println!("Writing to {}", attr);
            is_attr_writable(&rsclient, id, attr).unwrap()
        })
        .for_each(|is_ok| assert!(is_ok == is_writeable));
}

fn test_modify_group(rsclient: &KanidmClient, group_names: &[&str], is_modificable: bool) -> () {
    // need user test created to be added as test part
    group_names.iter().for_each(|group| {
        println!("Testing group: {}", group);
        ["description", "name"].iter().for_each(|attr| {
            assert!(is_attr_writable(&rsclient, group, attr).unwrap() == is_modificable)
        });
        assert!(rsclient.idm_group_add_members(group, &["test"]).is_ok() == is_modificable);
    });
}

// Users
// - Read to all self attributes (within security constraints).
// - Write to a limited set of self attributes, such as:
//     name, displayname, legalname, ssh-keys, credentials etc.
#[test]
fn test_default_entries_rbac_users() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();

        create_user_with_all_attrs(&mut rsclient, "self_account", Some("self_group"));
        create_user_with_all_attrs(&mut rsclient, "other_account", Some("other_group"));

        login_account(&mut rsclient, "self_account");

        test_read_attrs(&rsclient, "self_account", &USER_READABLE_ATTRS, true);
        test_read_attrs(&rsclient, "other_account", &USER_READABLE_ATTRS, true);

        static GROUP_READABLE_ATTRS: [&str; 5] = ["class", "name", "spn", "uuid", "member"];
        test_read_attrs(&rsclient, "self_group", &GROUP_READABLE_ATTRS, true);
        test_read_attrs(&rsclient, "other_group", &GROUP_READABLE_ATTRS, true);

        static USER_SENSITIVE_ATTRS: [&str; 2] = ["legalname", "mail"];
        test_read_attrs(&rsclient, "other_account", &USER_SENSITIVE_ATTRS, false);

        static SELF_READABLE_ATTRS: [&str; 1] = ["radius_secret"];
        test_read_attrs(&rsclient, "self_account", &SELF_READABLE_ATTRS, true);
        test_read_attrs(&rsclient, "other_account", &SELF_READABLE_ATTRS, false);

        test_write_attrs(&rsclient, "self_account", &SELF_WRITEABLE_ATTRS, true);
        test_write_attrs(&rsclient, "other_account", &SELF_WRITEABLE_ATTRS, false);

        static NON_SELF_WRITEABLE_ATTRS: [&str; 5] =
            ["spn", "class", "memberof", "gidnumber", "uuid"];
        test_write_attrs(&rsclient, "self_account", &NON_SELF_WRITEABLE_ATTRS, false);
    });
}

// Account Managers
// read and write to accounts, including write credentials but NOT private data (see people manager)
// ability to lock and unlock accounts, excluding high access members.
#[test]
fn test_default_entries_rbac_account_managers() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();

        create_user(&rsclient, "account_manager", "idm_account_manage_priv");
        create_user_with_all_attrs(&mut rsclient, "test", Some("test_group"));

        login_account(&mut rsclient, "account_manager");

        test_read_attrs(&rsclient, "test", &USER_READABLE_ATTRS, true);
        static ACCOUNT_MANAGER_ATTRS: [&str; 5] = [
            "name",
            "displayname",
            "primary_credential",
            "ssh_publickey",
            "mail",
        ];
        test_write_attrs(&rsclient, "test", &ACCOUNT_MANAGER_ATTRS, true);

        static PRIVATE_DATA_ATTRS: [&str; 1] = ["legalname"];
        test_read_attrs(&rsclient, "test", &PRIVATE_DATA_ATTRS, false);
        test_write_attrs(&rsclient, "test", &PRIVATE_DATA_ATTRS, false);
        // TODO #59: lock and _unlock, except high access members
    });
}

// Group Managers
// read all groups
// write group but not high access
#[test]
fn test_default_entries_rbac_group_managers() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();

        create_user(&rsclient, "group_manager", "idm_group_manage_priv");
        // create test user without creating new groups
        create_user(&rsclient, "test", "idm_admins");

        login_account(&mut rsclient, "group_manager");

        let default_group_names: HashSet<String> =
            [&DEFAULT_HP_GROUP_NAMES[..], &DEFAULT_NOT_HP_GROUP_NAMES[..]]
                .concat()
                .iter()
                .map(ToString::to_string)
                .collect();

        let groups = rsclient.idm_group_list().unwrap();
        let group_names: HashSet<String> = groups
            .iter()
            .map(|entry| entry.attrs.get("name").unwrap().first().unwrap())
            .cloned()
            .collect();
        assert_eq!(default_group_names, group_names);

        test_modify_group(&rsclient, &DEFAULT_HP_GROUP_NAMES, false);
        test_modify_group(&rsclient, &DEFAULT_NOT_HP_GROUP_NAMES, true);

        rsclient.idm_group_create("test_group").unwrap();
        rsclient
            .idm_group_add_members("test_group", &["test"])
            .unwrap();
        assert!(is_attr_writable(&rsclient, "test_group", "description").unwrap());
    });
}

// Admins
// read and write access control entries.
#[test]
fn test_default_entries_rbac_admins_access_control_entries() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        static ACP_COMMON_ATTRS: [&str; 4] =
            ["name", "description", "acp_receiver", "acp_targetscope"];
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

        ACP_ENTRIES.iter().for_each(|entry| {
            test_read_attrs(&rsclient, entry, &ACP_COMMON_ATTRS, true);
            test_write_attrs(&rsclient, entry, &ACP_COMMON_ATTRS, true);
        });
    });
}

// read schema entries.
// TODO #252: write schema entries
#[test]
fn test_default_entries_rbac_admins_schema_entries() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        let default_classnames: HashSet<String> = [
            "access_control_create",
            "access_control_delete",
            "access_control_modify",
            "access_control_profile",
            "access_control_search",
            "attributetype",
            "classtype",
            "extensibleobject",
            "memberof",
            "object",
            "recycled",
            "system",
            "system_info",
            "tombstone",
            "person",
            "group",
            "account",
            "domain_info",
            "posixaccount",
            "posixgroup",
            "system_config",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        let classtype_entries = rsclient.idm_schema_classtype_list().unwrap();
        let classnames: HashSet<String> = classtype_entries
            .iter()
            .map(|entry| entry.attrs.get("classname").unwrap().first().unwrap())
            .cloned()
            .collect();
        println!("{:?}", classnames);

        assert_eq!(default_classnames, classnames);

        let default_attributenames: HashSet<String> = [
            "acp_create_attr",
            "acp_create_class",
            "acp_enable",
            "acp_modify_class",
            "acp_modify_presentattr",
            "acp_modify_removedattr",
            "acp_receiver",
            "acp_search_attr",
            "acp_targetscope",
            "attributename",
            "claim",
            "class",
            "classname",
            "description",
            "directmemberof",
            "domain",
            "index",
            "last_modified_cid",
            "may",
            "member",
            "memberof",
            "multivalue",
            "must",
            "name",
            "password_import",
            "phantom",
            "spn",
            "syntax",
            "systemmay",
            "systemmust",
            "unique",
            "uuid",
            "version",
            "displayname",
            "legalname",
            "mail",
            "ssh_publickey",
            "primary_credential",
            "radius_secret",
            "domain_name",
            "domain_uuid",
            "domain_ssid",
            "gidnumber",
            "badlist_password",
            "loginshell",
            "unix_password",
            "nsuniqueid",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        let attributename_entries = rsclient.idm_schema_attributetype_list().unwrap();
        println!("{:?}", attributename_entries);
        let attributenames = attributename_entries
            .iter()
            .map(|entry| entry.attrs.get("attributename").unwrap().first().unwrap())
            .cloned()
            .collect();

        // I wonder if this should be a subset op?
        assert!(default_attributenames.is_subset(&attributenames));
    });
}

// modify all groups including high access groups.
// create new accounts (to bootstrap the system).
#[test]
fn test_default_entries_rbac_admins_group_entries() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        create_user(&rsclient, "test", "test_group");

        let default_group_names =
            [&DEFAULT_HP_GROUP_NAMES[..], &DEFAULT_NOT_HP_GROUP_NAMES[..]].concat();

        test_modify_group(&rsclient, &default_group_names, true);
    });
}

// modify high access accounts as an escalation for security sensitive accounts.
#[test]
fn test_default_entries_rbac_admins_ha_accounts() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();

        static MAIN_ATTRS: [&str; 3] = ["name", "displayname", "primary_credential"];
        test_write_attrs(&rsclient, "idm_admin", &MAIN_ATTRS, true);
    });
}

// recover from the recycle bin
#[test]
fn test_default_entries_rbac_admins_recycle_accounts() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        create_user(&rsclient, "test", "test_group");

        rsclient.idm_account_delete("test").unwrap();
        rsclient.recycle_bin_revive("test").unwrap();

        let acc = rsclient.idm_account_get("test").unwrap();
        assert!(acc.is_some());
    });
}

// People Managers
// read private or sensitive data of persons, IE legalName
// write private or sensitive data of persons, IE legalName
#[test]
fn test_default_entries_rbac_people_managers() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();

        create_user(&rsclient, "read_people_manager", "idm_people_read_priv");
        create_user_with_all_attrs(&mut rsclient, "test", Some("test_group"));

        static PEOPLE_MANAGER_ATTRS: [&str; 2] = ["legalname", "mail"];

        static TECHNICAL_ATTRS: [&str; 3] =
            ["primary_credential", "radius_secret", "unix_password"];
        test_read_attrs(&rsclient, "test", &PEOPLE_MANAGER_ATTRS, true);

        login_account(&mut rsclient, "read_people_manager");

        test_read_attrs(&rsclient, "test", &PEOPLE_MANAGER_ATTRS, true);
        test_read_attrs(&rsclient, "test", &TECHNICAL_ATTRS, false);
        test_write_attrs(&rsclient, "test", &PEOPLE_MANAGER_ATTRS, false);
        test_write_attrs(&rsclient, "test", &TECHNICAL_ATTRS, false);

        let _ = rsclient.logout();
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        create_user(&rsclient, "write_people_manager", "idm_people_write_priv");
        login_account(&mut rsclient, "write_people_manager");

        test_read_attrs(&rsclient, "test", &PEOPLE_MANAGER_ATTRS, true);
        test_read_attrs(&rsclient, "test", &TECHNICAL_ATTRS, false);
        test_write_attrs(&rsclient, "test", &PEOPLE_MANAGER_ATTRS, true);
        test_write_attrs(&rsclient, "test", &TECHNICAL_ATTRS, false);
    });
}

// Anonymous Clients + Everyone Else
// read memberof, unix attrs, name, displayname, class
#[test]
fn test_default_entries_rbac_anonymous_entry() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        create_user_with_all_attrs(&mut rsclient, "test", Some("test_group"));
        rsclient
            .idm_group_add_members("test_group", &["anonymous"])
            .unwrap();
        add_all_attrs(&mut rsclient, "anonymous", "test_group");

        let _ = rsclient.logout();
        rsclient.auth_anonymous().unwrap();

        test_read_attrs(&rsclient, "test", &USER_READABLE_ATTRS, true);
        test_read_attrs(&rsclient, "anonymous", &USER_READABLE_ATTRS, true);
        test_write_attrs(&rsclient, "test", &SELF_WRITEABLE_ATTRS, false);
        test_write_attrs(&rsclient, "anonymous", &SELF_WRITEABLE_ATTRS, false);
    });
}

// RADIUS Servers
// Read radius credentials
// Read other needed attributes to fulfil radius functions.
#[test]
fn test_default_entries_rbac_radius_servers() {
    run_test(|mut rsclient: KanidmClient| {
        rsclient
            .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
            .unwrap();
        create_user(&rsclient, "radius_server", "idm_radius_servers");
        create_user_with_all_attrs(&mut rsclient, "test", Some("test_group"));

        login_account(&mut rsclient, "radius_server");
        static RADIUS_NECESSARY_ATTRS: [&str; 4] = ["name", "spn", "uuid", "radius_secret"];

        test_read_attrs(&rsclient, "test", &USER_READABLE_ATTRS, true);
        test_read_attrs(&rsclient, "test", &RADIUS_NECESSARY_ATTRS, true);
        test_write_attrs(&rsclient, "test", &RADIUS_NECESSARY_ATTRS, false);
    });
}
