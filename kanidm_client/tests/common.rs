use std::net::TcpStream;
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, IntegrationTestConfig};
use score::create_server_core;
use kanidm::tracing_tree;
use kanidm_client::{KanidmClient, KanidmClientBuilder};

use async_std::task;
use tokio::sync::mpsc;

pub const ADMIN_TEST_USER: &str = "admin";
pub const ADMIN_TEST_PASSWORD: &str = "integration test admin password";
static PORT_ALLOC: AtomicU16 = AtomicU16::new(18080);

fn is_free_port(port: u16) -> bool {
    // TODO: Refactor to use `Result::is_err` in a future PR
    match TcpStream::connect(("0.0.0.0", port)) {
        Ok(_) => false,
        Err(_) => true,
    }
}

// Test external behaviours of the service.

pub fn run_test(test_fn: fn(KanidmClient) -> ()) {
    let _ = tracing_tree::test_init();

    let (ready_tx, mut ready_rx) = mpsc::channel(1);
    let (finish_tx, mut finish_rx) = mpsc::channel(1);

    let mut counter = 0;
    let port = loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        if counter >= 5 {
            eprintln!("Unable to allocate port!");
            assert!(false);
        }
    };

    let int_config = Box::new(IntegrationTestConfig {
        admin_user: ADMIN_TEST_USER.to_string(),
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
    });

    // Setup the config ...
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.secure_cookies = false;
    config.integration_test_config = Some(int_config);
    config.log_level = Some(LogLevel::Quiet as u32);
    // config.log_level = Some(LogLevel::Verbose as u32);
    // config.log_level = Some(LogLevel::FullTrace as u32);
    config.threads = 1;

    let t_handle = thread::spawn(move || {
        // Spawn a thread for the test runner, this should have a unique
        // port....
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start tokio");
        rt.block_on(async {
            create_server_core(config, false)
                .await
                .expect("failed to start server core");
            // We have to yield now to guarantee that the tide elements are setup.
            task::yield_now().await;
            ready_tx
                .send(())
                .await
                .expect("failed in indicate readiness");
            finish_rx.recv().await;
        });
    });

    let _ = task::block_on(ready_rx.recv()).expect("failed to start ctx");
    // Do we need any fixtures?
    // Yes probably, but they'll need to be futures as well ...
    // later we could accept fixture as it's own future for re-use

    // Setup the client, and the address we selected.
    let addr = format!("http://127.0.0.1:{}", port);
    let rsclient = KanidmClientBuilder::new()
        .address(addr)
        .no_proxy()
        .build()
        .expect("Failed to build client");

    test_fn(rsclient);

    // We DO NOT need teardown, as sqlite is in mem
    // let the tables hit the floor

    // At this point, when the channel drops, it drops the thread too.
    task::block_on(finish_tx.send(())).expect("unable to send to ctx");
    t_handle.join().expect("failed to join thread");
}
