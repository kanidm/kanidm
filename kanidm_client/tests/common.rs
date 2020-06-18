use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, IntegrationTestConfig};
use kanidm::core::create_server_core;
use kanidm_client::{KanidmClient, KanidmClientBuilder};

use actix::prelude::*;

pub const ADMIN_TEST_PASSWORD: &str = "integration test admin password";
static PORT_ALLOC: AtomicUsize = AtomicUsize::new(8080);

// Test external behaviours of the service.

pub fn run_test(test_fn: fn(KanidmClient) -> ()) {
    // ::std::env::set_var("RUST_LOG", "actix_web=warn,kanidm=error");
    let _ = env_logger::builder()
        .format_timestamp(None)
        .format_level(false)
        .is_test(true)
        .try_init();

    let (tx, rx) = mpsc::channel();
    let port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);

    let int_config = Box::new(IntegrationTestConfig {
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
    });

    // Setup the config ...
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.secure_cookies = false;
    config.integration_test_config = Some(int_config);
    config.log_level = Some(LogLevel::Quiet as u32);
    thread::spawn(move || {
        // Spawn a thread for the test runner, this should have a unique
        // port....
        let system = System::new("test-rctx");

        let rctx = async move {
            let sctx = create_server_core(config).await;
            let _ = tx.send(sctx);
        };

        Arbiter::spawn(rctx);

        system.run().expect("Failed to start thread");
    });
    let sctx = rx.recv().unwrap().expect("failed to start ctx");
    System::set_current(sctx.current());

    // Do we need any fixtures?
    // Yes probably, but they'll need to be futures as well ...
    // later we could accept fixture as it's own future for re-use

    // Setup the client, and the address we selected.
    let addr = format!("http://127.0.0.1:{}", port);
    let rsclient = KanidmClientBuilder::new()
        .address(addr)
        .build()
        .expect("Failed to build client");

    test_fn(rsclient);

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
    sctx.stop();
}
