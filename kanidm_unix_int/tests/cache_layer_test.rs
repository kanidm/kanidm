use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use actix::prelude::*;
use kanidm::config::{Configuration, IntegrationTestConfig};
use kanidm::core::create_server_core;
use log::debug;

use kanidm_unix_common::cache::CacheLayer;
use tokio::runtime::Runtime;

use kanidm_client::KanidmClientBuilder;

static PORT_ALLOC: AtomicUsize = AtomicUsize::new(18080);
static ADMIN_TEST_PASSWORD: &str = "integration test admin password";
static ADMIN_TEST_PASSWORD_CHANGE: &str = "integration test admin new🎉";

fn run_test(test_fn: fn(CacheLayer) -> ()) {
    // ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
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
    let rsclient = KanidmClientBuilder::new()
        .address(addr)
        .build_async()
        .expect("Failed to build client");

    let cachelayer = CacheLayer::new(
        "", // The sqlite db path, this is in memory.
        300, rsclient,
    )
    .expect("Failed to build cache layer.");

    test_fn(cachelayer);

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor
    sys.stop();
}

#[test]
fn test_cache_sshkey() {
    run_test(|cachelayer| {
        let mut rt = Runtime::new().expect("Failed to start tokio");
        let fut = async move {
            assert!(cachelayer.test_connection().await);
        };
        rt.block_on(fut);
    })
}
