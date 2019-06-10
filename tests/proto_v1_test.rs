extern crate actix;
use actix::prelude::*;

extern crate rsidm;
use rsidm::config::Configuration;
use rsidm::constants::UUID_ADMIN;
use rsidm::core::create_server_core;
use rsidm::proto_v1::{CreateRequest, Entry, OperationResponse};

extern crate reqwest;

extern crate futures;
// use futures::future;
// use futures::future::Future;

use std::sync::mpsc;
use std::thread;

extern crate tokio;

// Test external behaviorus of the service.

macro_rules! run_test {
    ($test_fn:expr) => {{
        let (tx, rx) = mpsc::channel();
        let config = Configuration::new();
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
        let addr = "http://127.0.0.1:8080";

        $test_fn(client, addr);

        // We DO NOT need teardown, as sqlite is in mem
        // let the tables hit the floor
        let _ = sys.stop();
    }};
}

#[test]
fn test_server_proto() {
    run_test!(|client, addr| {
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

        let mut response = client
            .post(concat!(addr, "/v1/create"))
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
    run_test!(|client, addr| {
        
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
