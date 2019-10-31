#![deny(warnings)]

#[macro_use]
extern crate log;

extern crate actix;
use actix::prelude::*;

extern crate kanidm;
extern crate kanidm_client;
extern crate kanidm_proto;
extern crate serde_json;

use kanidm_client::KanidmClient;

use kanidm::config::{Configuration, IntegrationTestConfig};
use kanidm::core::create_server_core;
use kanidm_proto::v1::{Entry, Filter, Modify, ModifyList};

extern crate reqwest;

extern crate futures;
// use futures::future;
// use futures::future::Future;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

extern crate env_logger;
extern crate tokio;

static PORT_ALLOC: AtomicUsize = AtomicUsize::new(8080);
static ADMIN_TEST_PASSWORD: &'static str = "integration test admin password";
static ADMIN_TEST_PASSWORD_CHANGE: &'static str = "integration test admin new🎉";

// Test external behaviorus of the service.

fn run_test(test_fn: fn(KanidmClient) -> ()) {
    ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
    let _ = env_logger::builder().is_test(true).try_init();
    let (tx, rx) = mpsc::channel();
    let port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);

    let int_config = Box::new(IntegrationTestConfig {
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
    });

    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.secure_cookies = false;
    config.integration_test_config = Some(int_config);
    // Setup the config ...

    thread::spawn(move || {
        // Spawn a thread for the test runner, this should have a unique
        // port....
        System::run(move || {
            create_server_core(config);

            // This appears to be bind random ...
            // let srv = srv.bind("127.0.0.1:0").unwrap();
            let _ = tx.send(System::current());
        });
    });
    let sys = rx.recv().unwrap();
    System::set_current(sys.clone());

    // Do we need any fixtures?
    // Yes probably, but they'll need to be futures as well ...
    // later we could accept fixture as it's own future for re-use

    // Setup the client, and the address we selected.
    let addr = format!("http://127.0.0.1:{}", port);
    let rsclient = KanidmClient::new(addr.as_str(), None);

    test_fn(rsclient);

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
    let _ = sys.stop();
}

#[test]
fn test_server_create() {
    run_test(|rsclient: KanidmClient| {
        let e: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["person", "account"],
                "name": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .unwrap();

        // Not logged in - should fail!
        let res = rsclient.create(vec![e.clone()]);
        assert!(res.is_err());

        let a_res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(a_res.is_ok());

        let res = rsclient.create(vec![e]);
        assert!(res.is_ok());
    });
}

#[test]
fn test_server_modify() {
    run_test(|rsclient: KanidmClient| {
        // Build a self mod.

        let f = Filter::SelfUUID;
        let m = ModifyList::new_list(vec![
            Modify::Purged("displayname".to_string()),
            Modify::Present("displayname".to_string(), "test".to_string()),
        ]);

        // Not logged in - should fail!
        let res = rsclient.modify(f.clone(), m.clone());
        assert!(res.is_err());

        let a_res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(a_res.is_ok());

        let res = rsclient.modify(f.clone(), m.clone());
        println!("{:?}", res);
        assert!(res.is_ok());
    });
}

#[test]
fn test_server_whoami_anonymous() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        // Now login as anonymous
        let res = rsclient.auth_anonymous();
        assert!(res.is_ok());

        // Now do a whoami.
        let (_e, uat) = match rsclient.whoami().unwrap() {
            Some((e, uat)) => (e, uat),
            None => panic!(),
        };
        debug!("{}", uat);
        assert!(uat.name == "anonymous");
    });
}

#[test]
fn test_server_whoami_admin_simple_password() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Now do a whoami.
        let (_e, uat) = match rsclient.whoami().unwrap() {
            Some((e, uat)) => (e, uat),
            None => panic!(),
        };
        debug!("{}", uat);
        assert!(uat.name == "admin");
    });
}

#[test]
fn test_server_search() {
    run_test(|rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        let rset = rsclient
            .search(Filter::Eq("name".to_string(), "admin".to_string()))
            .unwrap();
        println!("{:?}", rset);
        let e = rset.first().unwrap();
        // Check it's admin.
        println!("{:?}", e);
        let name = e.attrs.get("name").unwrap();
        assert!(name == &vec!["admin".to_string()]);
    });
}

#[test]
fn test_server_admin_change_simple_password() {
    run_test(|mut rsclient: KanidmClient| {
        // First show we are un-authenticated.
        let pre_res = rsclient.whoami();
        // This means it was okay whoami, but no uat attached.
        assert!(pre_res.unwrap().is_none());

        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Now change the password.
        let _ = rsclient
            .idm_account_set_password(ADMIN_TEST_PASSWORD_CHANGE.to_string())
            .unwrap();

        // Now "reset" the client.
        let _ = rsclient.logout();
        // Old password fails
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_err());
        // New password works!
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD_CHANGE);
        assert!(res.is_ok());
    });
}

// Add a test for reseting another accounts pws via the rest api
#[test]
fn test_server_admin_reset_simple_password() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());
        // Create a diff account
        let e: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["person", "account"],
                "name": ["testperson"],
                "displayname": ["testperson"]
            }
        }"#,
        )
        .unwrap();

        // Not logged in - should fail!
        let res = rsclient.create(vec![e.clone()]);
        assert!(res.is_ok());
        // By default, admin's can't actually administer accounts, so mod them into
        // the account admin group.
        let f = Filter::Eq("name".to_string(), "idm_account_write_priv".to_string());
        let m = ModifyList::new_list(vec![Modify::Present(
            "member".to_string(),
            "idm_admins".to_string(),
        )]);
        let res = rsclient.modify(f.clone(), m.clone());
        assert!(res.is_ok());

        // Now set it's password.
        let res = rsclient.idm_account_primary_credential_set_password("testperson", "password");
        assert!(res.is_ok());
        // Check it stuck.
        let tclient = rsclient.new_session();
        assert!(tclient
            .auth_simple_password("testperson", "password")
            .is_ok());

        // Generate a pw instead
        let res = rsclient.idm_account_primary_credential_set_generated("testperson");
        assert!(res.is_ok());
        let gpw = res.unwrap();
        let tclient = rsclient.new_session();
        assert!(tclient
            .auth_simple_password("testperson", gpw.as_str())
            .is_ok());
    });
}

// test the rest group endpoint.
#[test]
fn test_server_rest_group_read() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the groups
        let g_list = rsclient.idm_group_list().unwrap();
        assert!(g_list.len() > 0);

        let g = rsclient.idm_group_get("idm_admins").unwrap();
        assert!(g.is_some());
        println!("{:?}", g);
    });
}

#[test]
fn test_server_rest_group_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the groups
        let g_list = rsclient.idm_group_list().unwrap();
        assert!(g_list.len() > 0);

        // Create a new group
        rsclient.idm_group_create("demo_group").unwrap();

        // List again, ensure one more.
        let g_list_2 = rsclient.idm_group_list().unwrap();
        assert!(g_list_2.len() > g_list.len());

        // Test modifications to the group

        // Add a member.
        rsclient
            .idm_group_add_members("demo_group", vec!["admin"])
            .unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members == vec!["admin".to_string()]);

        // Set the list of members
        rsclient
            .idm_group_set_members("demo_group", vec!["admin", "demo_group"])
            .unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members == vec!["admin".to_string(), "demo_group".to_string()]);

        // Remove a member from the group
        /*
        rsclient
            .idm_group_remove_member("demo_group", "demo_group")
            .unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members == vec!["admin".to_string()]);
        */

        // purge members
        rsclient.idm_group_purge_members("demo_group").unwrap();
        let members = rsclient.idm_group_get_members("demo_group").unwrap();
        assert!(members.len() == 0);

        // Delete the group
        rsclient.idm_group_delete("demo_group").unwrap();
        let g_list_3 = rsclient.idm_group_list().unwrap();
        assert!(g_list_3.len() == g_list.len());

        // Check we can get an exact group
        let g = rsclient.idm_group_get("idm_admins").unwrap();
        assert!(g.is_some());
        println!("{:?}", g);

        // They should have members
        let members = rsclient.idm_group_get_members("idm_admins").unwrap();
        println!("{:?}", members);
        assert!(members == vec!["admin".to_string()]);
    });
}

#[test]
fn test_server_rest_account_read() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the accounts
        let a_list = rsclient.idm_account_list().unwrap();
        assert!(a_list.len() > 0);

        let a = rsclient.idm_account_get("admin").unwrap();
        assert!(a.is_some());
        println!("{:?}", a);
    });
}

#[test]
fn test_server_rest_schema_read() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // List the schema
        let s_list = rsclient.idm_schema_list().unwrap();
        assert!(s_list.len() > 0);

        let a_list = rsclient.idm_schema_attributetype_list().unwrap();
        assert!(a_list.len() > 0);

        let c_list = rsclient.idm_schema_classtype_list().unwrap();
        assert!(c_list.len() > 0);

        // Get an attr/class
        let a = rsclient.idm_schema_attributetype_get("name").unwrap();
        assert!(a.is_some());
        println!("{:?}", a);

        let c = rsclient.idm_schema_classtype_get("account").unwrap();
        assert!(c.is_some());
        println!("{:?}", c);
    });
}

// Test resetting a radius cred, and then checking/viewing it.
#[test]
fn test_server_radius_credential_lifecycle() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Should have no radius secret
        let n_sec = rsclient.idm_account_radius_credential_get("admin").unwrap();
        assert!(n_sec.is_none());

        // Set one
        let sec1 = rsclient
            .idm_account_radius_credential_regenerate("admin")
            .unwrap();

        // Should be able to get it.
        let r_sec = rsclient.idm_account_radius_credential_get("admin").unwrap();
        assert!(sec1 == r_sec.unwrap());

        // test getting the token - we can do this as self or the radius server
        let r_tok = rsclient.idm_account_radius_token_get("admin").unwrap();
        assert!(sec1 == r_tok.secret);
        assert!(r_tok.name == "admin".to_string());

        // Reset it
        let sec2 = rsclient
            .idm_account_radius_credential_regenerate("admin")
            .unwrap();

        // Should be different
        println!("s1 {} != s2 {}", sec1, sec2);
        assert!(sec1 != sec2);

        // Delete it
        let res = rsclient.idm_account_radius_credential_delete("admin");
        assert!(res.is_ok());

        // No secret
        let n_sec = rsclient.idm_account_radius_credential_get("admin").unwrap();
        assert!(n_sec.is_none());
    });
}

// Test the self version of the radius path.

// Test hitting all auth-required endpoints and assert they give unauthorized.
