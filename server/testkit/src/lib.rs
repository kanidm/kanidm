#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::net::TcpStream;
use std::sync::atomic::{AtomicU16, Ordering};

use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidmd_core::config::{Configuration, IntegrationTestConfig, ServerRole};
use kanidmd_core::{create_server_core, CoreHandle};
use tokio::task;

pub const ADMIN_TEST_USER: &str = "admin";
pub const ADMIN_TEST_PASSWORD: &str = "integration test admin password";

pub const NOT_ADMIN_TEST_USERNAME: &str = "krab_test_user";
pub const NOT_ADMIN_TEST_PASSWORD: &str = "eicieY7ahchaoCh0eeTa";

pub static PORT_ALLOC: AtomicU16 = AtomicU16::new(18080);

pub use testkit_macros::test;

pub fn is_free_port(port: u16) -> bool {
    TcpStream::connect(("0.0.0.0", port)).is_err()
}

// Test external behaviours of the service.

// allowed because the use of this function is behind a test gate
#[allow(dead_code)]
pub async fn setup_async_test() -> (KanidmClient, CoreHandle) {
    sketching::test_init();

    let mut counter = 0;
    let port = loop {
        let possible_port = PORT_ALLOC.fetch_add(1, Ordering::SeqCst);
        if is_free_port(possible_port) {
            break possible_port;
        }
        counter += 1;
        #[allow(clippy::panic)]
        if counter >= 5 {
            eprintln!("Unable to allocate port!");
            panic!();
        }
    };

    let int_config = Box::new(IntegrationTestConfig {
        admin_user: ADMIN_TEST_USER.to_string(),
        admin_password: ADMIN_TEST_PASSWORD.to_string(),
    });

    let addr = format!("http://localhost:{}", port);

    // Setup the config ...
    let mut config = Configuration::new();
    config.address = format!("127.0.0.1:{}", port);
    config.secure_cookies = false;
    config.integration_test_config = Some(int_config);
    config.role = ServerRole::WriteReplica;
    config.domain = "localhost".to_string();
    config.origin = addr.clone();
    config.threads = 1;

    let core_handle = match create_server_core(config, false).await {
        Ok(val) => val,
        #[allow(clippy::panic)]
        Err(_) => panic!("failed to start server core"),
    };
    // We have to yield now to guarantee that the elements are setup.
    task::yield_now().await;

    #[allow(clippy::panic)]
    let rsclient = match KanidmClientBuilder::new()
        .address(addr.clone())
        .no_proxy()
        .build()
    {
        Ok(val) => val,
        Err(_) => panic!("failed to build client"),
    };

    tracing::info!("Testkit server setup complete - {}", addr);

    (rsclient, core_handle)
}
