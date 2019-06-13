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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

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
    let client = reqwest::Client::new();
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
        // Now login as anonymous
        // Now do a whoami.
    });
}

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
