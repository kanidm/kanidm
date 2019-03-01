extern crate actix;
use actix::prelude::*;

extern crate rsidm;
use rsidm::config::Configuration;
use rsidm::core::create_server_core;
use rsidm::proto_v1::{CreateRequest, Entry, OperationResponse, SearchRequest, SearchResponse};

extern crate reqwest;

extern crate futures;
use futures::future;
use futures::future::Future;

use std::sync::mpsc;
use std::thread;

extern crate tokio;

// Test external behaviorus of the service.

macro_rules! run_test {
    ($test_fn:expr) => {{
        let (tx, rx) = mpsc::channel();

        thread::spawn(|| {
            // setup
            // Create a server config in memory for use - use test settings
            // Create a log: In memory - for now it's just stdout

            System::run(move || {
                let config = Configuration::new();
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
        $test_fn();

        // We DO NOT need teardown, as sqlite is in mem
        // let the tables hit the floor
        let _ = sys.stop();
    }};
}

#[test]
fn test_server_proto() {
    run_test!(|| {
        let client = reqwest::Client::new();

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

        let c = CreateRequest { entries: vec![e] };

        let mut response = client
            .post("http://127.0.0.1:8080/v1/create")
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
