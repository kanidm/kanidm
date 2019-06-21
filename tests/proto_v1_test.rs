extern crate actix;
use actix::prelude::*;

extern crate rsidm;
use rsidm::config::Configuration;
use rsidm::constants::UUID_ADMIN;
use rsidm::core::create_server_core;
use rsidm::proto_v1::{CreateRequest, Entry, OperationResponse, WhoamiRequest};

extern crate reqwest;

extern crate futures;
// use futures::future;
// use futures::future::Future;

use std::sync::mpsc;
use std::thread;
use std::sync::atomic::{AtomicUsize, Ordering};

extern crate tokio;

static PORT_ALLOC: AtomicUsize = AtomicUsize::new(8080);

// Test external behaviorus of the service.

fn run_test(test_fn: fn(reqwest::Client, &str) -> ()) {
    let (tx, rx) = mpsc::channel();
    let port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
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
        let whoami_dest = format!("{}/v1/create", addr);
        let auth_dest = format!("{}/v1/auth", addr);

        let mut response = client
            .get(whoami_dest.as_str());
            .send()
            .unwrap();

        // https://docs.rs/reqwest/0.9.15/reqwest/struct.Response.html
        println!("{:?}", response);

        assert!(response.status() == reqwest::StatusCode::UNAUTHORIZED);

        // Now login as anonymous
        // This sets a cookie to say who you are:
        // Initiate - this should say what details are needed.

        // Send the credentials required

        let mut response = client
            .post(auth_dest.as_str())
            // .body()
            .send()
            .unwrap()
        assert!(response.status() == reqwest::StatusCode::OK);

        // Now do a whoami.
        let mut response = client
            .get(whoami_dest.as_str());
            .send()
            .unwrap();
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
