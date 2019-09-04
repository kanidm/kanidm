#![deny(warnings)]

#[macro_use]
extern crate log;

extern crate actix;
use actix::prelude::*;

extern crate rsidm;
extern crate rsidm_proto;
extern crate serde_json;

use rsidm::config::{Configuration, IntegrationTestConfig};
use rsidm::constants::UUID_ADMIN;
use rsidm::core::create_server_core;
use rsidm_proto::v1::{
    AuthCredential, AuthRequest, AuthResponse, AuthState, AuthStep, CreateRequest, Entry,
    OperationResponse,
};

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

fn run_test(test_fn: fn(reqwest::Client, &str) -> ()) {
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
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("Unexpected reqwest builder failure!");
    let addr = format!("http://127.0.0.1:{}", port);

    test_fn(client, addr.as_str());

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
    let _ = sys.stop();
}

#[test]
fn test_server_proto() {
    run_test(|client: reqwest::Client, addr: &str| {
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

        let c = CreateRequest {
            entries: vec![e],
            user_uuid: UUID_ADMIN.to_string(),
        };

        let dest = format!("{}/v1/create", addr);

        let mut response = client
            .post(dest.as_str())
            .body(serde_json::to_string(&c).unwrap())
            .send()
            .unwrap();

        println!("{:?}", response);
        let r: OperationResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();

        println!("{:?}", r);

        // deserialise the response here
        // check it's valid.

        ()
    });
}

#[test]
fn test_server_whoami_anonymous() {
    run_test(|client: reqwest::Client, addr: &str| {
        // First show we are un-authenticated.
        let whoami_dest = format!("{}/v1/whoami", addr);
        let auth_dest = format!("{}/v1/auth", addr);

        let response = client.get(whoami_dest.as_str()).send().unwrap();

        // https://docs.rs/reqwest/0.9.15/reqwest/struct.Response.html
        println!("{:?}", response);

        assert!(response.status() == reqwest::StatusCode::UNAUTHORIZED);

        // Now login as anonymous

        // Setup the auth initialisation
        let auth_init = AuthRequest {
            step: AuthStep::Init("anonymous".to_string(), None),
        };

        let mut response = client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_init).unwrap())
            .send()
            .unwrap();
        assert!(response.status() == reqwest::StatusCode::OK);
        // Check that we got the next step
        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();
        println!("==> AUTHRESPONSE ==> {:?}", r);

        assert!(match &r.state {
            AuthState::Continue(_all_list) => {
                // Check anonymous is present? It will fail on next step if not ...
                true
            }
            _ => false,
        });

        // Send the credentials required now
        let auth_anon = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Anonymous]),
        };

        let mut response = client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_anon).unwrap())
            .send()
            .unwrap();
        debug!("{}", response.status());
        assert!(response.status() == reqwest::StatusCode::OK);
        // Check that we got the next step
        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();
        println!("==> AUTHRESPONSE ==> {:?}", r);

        assert!(match &r.state {
            AuthState::Success(uat) => {
                println!("==> Authed as uat; {:?}", uat);
                true
            }
            _ => false,
        });

        // Now do a whoami.
        let mut response = client.get(whoami_dest.as_str()).send().unwrap();
        println!("WHOAMI -> {}", response.text().unwrap().as_str());
        println!("WHOAMI STATUS -> {}", response.status());
        assert!(response.status() == reqwest::StatusCode::OK);

        // Check the json now ... response.json()
    });
}

#[test]
fn test_server_whoami_admin_simple_password() {
    run_test(|client: reqwest::Client, addr: &str| {
        // First show we are un-authenticated.
        let whoami_dest = format!("{}/v1/whoami", addr);
        let auth_dest = format!("{}/v1/auth", addr);
        // Now login as admin

        // Setup the auth initialisation
        let auth_init = AuthRequest {
            step: AuthStep::Init("admin".to_string(), None),
        };

        let mut response = client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_init).unwrap())
            .send()
            .unwrap();
        assert!(response.status() == reqwest::StatusCode::OK);
        // Check that we got the next step
        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();
        println!("==> AUTHRESPONSE ==> {:?}", r);

        assert!(match &r.state {
            AuthState::Continue(_all_list) => {
                // Check anonymous is present? It will fail on next step if not ...
                true
            }
            _ => false,
        });

        // Send the credentials required now
        let auth_admin = AuthRequest {
            step: AuthStep::Creds(vec![AuthCredential::Password(
                ADMIN_TEST_PASSWORD.to_string(),
            )]),
        };

        let mut response = client
            .post(auth_dest.as_str())
            .body(serde_json::to_string(&auth_admin).unwrap())
            .send()
            .unwrap();
        debug!("{}", response.status());
        assert!(response.status() == reqwest::StatusCode::OK);
        // Check that we got the next step
        let r: AuthResponse = serde_json::from_str(response.text().unwrap().as_str()).unwrap();
        println!("==> AUTHRESPONSE ==> {:?}", r);

        assert!(match &r.state {
            AuthState::Success(uat) => {
                println!("==> Authed as uat; {:?}", uat);
                true
            }
            _ => false,
        });

        // Now do a whoami.
        let mut response = client.get(whoami_dest.as_str()).send().unwrap();
        println!("WHOAMI -> {}", response.text().unwrap().as_str());
        println!("WHOAMI STATUS -> {}", response.status());
        assert!(response.status() == reqwest::StatusCode::OK);

        // Check the json now ... response.json()
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
