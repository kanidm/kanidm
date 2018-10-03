extern crate actix;
use actix::prelude::*;

use std::panic;

extern crate rsidm;
use rsidm::log::{self, EventLog, LogEvent};
use rsidm::server::{self, QueryServer};
// use be;

extern crate futures;
use futures::future::Future;
use futures::future::lazy;
use futures::future;

extern crate tokio;
use tokio::executor::current_thread::CurrentThread;

// Test external behaviorus of the service.

macro_rules! run_test {
    ($test_fn:expr) => {{
        System::run(|| {
            // setup
            // Create a server config in memory for use - use test settings
            // Create a log: In memory - for now it's just stdout
            let test_log = log::start();
            // Create the db as a temporary, see:
            //     https://sqlite.org/inmemorydb.html

            let test_server = server::start(test_log.clone(), "", 1);

            // Do we need any fixtures?
            // Yes probably, but they'll need to be futures as well ...
            // later we could accept fixture as it's own future for re-use
            // For now these can also bypass the FE code
            // let fixture_fut = ();

            // We have to spawn every test as a future
            let fut = $test_fn(test_log, test_server);

            // Now chain them ...
            // Now append the server shutdown.
            let comp_fut = fut.map_err(|_| ())
                .and_then(|r| {
                    println!("Stopping actix ...");
                    actix::System::current().stop();
                    future::result(Ok(()))
                });

            // Run the future
            tokio::spawn(comp_fut);
            // We DO NOT need teardown, as sqlite is in mem
            // let the tables hit the floor
        });

    }};
}

#[test]
fn test_schema() {
    run_test!(|log: actix::Addr<EventLog>, server| {
        log.send(LogEvent {
            msg: String::from("Test log event")
        })
    });
}

/*
#[test]
fn test_be_create_user() {
    run_test!(|log, be, server| {
        println!("It works");
    });
}
*/

