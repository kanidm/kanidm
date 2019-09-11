#![deny(warnings)]

#[macro_use]
extern crate log;

extern crate actix;
use actix::prelude::*;

extern crate rsidm;
extern crate rsidm_client;
extern crate rsidm_proto;
extern crate serde_json;

use rsidm_client::RsidmClient;

use rsidm::config::{Configuration, IntegrationTestConfig};
use rsidm::core::create_server_core;
use rsidm_proto::v1::Entry;

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

// Test external behaviorus of the service.

fn run_test(test_fn: fn(RsidmClient) -> ()) {
    // ::std::env::set_var("RUST_LOG", "actix_web=debug,rsidm=debug");
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
    let rsclient = RsidmClient::new(addr.as_str());

    test_fn(rsclient);

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
    let _ = sys.stop();
}

#[test]
fn test_server_create() {
    run_test(|rsclient: RsidmClient| {
        let e: Entry = serde_json::from_str(
            r#"{
            "attrs": {
                "class": ["person"],
                "name": ["testperson"],
                "description": ["testperson"],
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
fn test_server_whoami_anonymous() {
    run_test(|rsclient: RsidmClient| {
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
    run_test(|rsclient: RsidmClient| {
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

// Test hitting all auth-required endpoints and assert they give unauthorized.

/*
#[test]
fn test_be_create_user() {
    run_test!(|log, server: actix::Addr<QueryServer>| {
        let r1 = server.search();
        assert!(r1.len() == 0);

        let cr = server.create();
        assert!(cr.is_ok());

        let r2 = server.search();
        assert!(r2.len() == 1);

        future::ok(())
    });
}
*/
