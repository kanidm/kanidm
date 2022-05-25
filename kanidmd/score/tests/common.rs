use std::net::TcpStream;
use std::sync::atomic::{AtomicU16, Ordering};

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, IntegrationTestConfig, ServerRole};
use kanidm::tracing_tree;
use kanidm_client::{KanidmClient, KanidmClientBuilder};
use score::create_server_core;
use tokio::task;

pub const ADMIN_TEST_USER: &str = "admin";
pub const ADMIN_TEST_PASSWORD: &str = "integration test admin password";
pub static PORT_ALLOC: AtomicU16 = AtomicU16::new(18080);

pub fn is_free_port(port: u16) -> bool {
    // TODO: Refactor to use `Result::is_err` in a future PR
    match TcpStream::connect(("0.0.0.0", port)) {
        Ok(_) => false,
        Err(_) => true,
    }
}

// Test external behaviours of the service.

// allowed because the use of this function is behind a test gate
#[allow(dead_code)]
pub async fn setup_async_test() -> KanidmClient {
    let _ = tracing_tree::test_init();

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
    config.role = ServerRole::WriteReplicaNoUI;
    // config.log_level = Some(LogLevel::Verbose as u32);
    // config.log_level = Some(LogLevel::FullTrace as u32);
    config.threads = 1;

    create_server_core(config, false)
        .await
        .expect("failed to start server core");
    // We have to yield now to guarantee that the tide elements are setup.
    task::yield_now().await;

    let addr = format!("http://127.0.0.1:{}", port);
    let rsclient = KanidmClientBuilder::new()
        .address(addr)
        .no_proxy()
        .build()
        .expect("Failed to build client");

    rsclient
}
