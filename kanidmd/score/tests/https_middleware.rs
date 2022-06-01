use std::sync::atomic::Ordering;

mod common;
use crate::common::{ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, PORT_ALLOC};

use kanidm::audit::LogLevel;
use kanidm::config::{Configuration, IntegrationTestConfig, ServerRole};
use kanidm::tracing_tree;
use score::create_server_core;
use tokio::task;

use crate::common::is_free_port;

#[tokio::test]
async fn test_https_middleware_headers() {
    // tests stuff
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
    config.role = ServerRole::WriteReplica;
    config.threads = 1;

    create_server_core(config, false)
        .await
        .expect("failed to start server core");
    // We have to yield now to guarantee that the tide elements are setup.
    task::yield_now().await;

    let addr = format!("http://127.0.0.1:{}/", port);

    // here we test the /ui/ endpoint which should have the headers
    let response = match reqwest::get(format!("{}ui/", &addr)).await {
        Ok(value) => value,
        Err(error) => {
            panic!("Failed to query {:?} : {:#?}", addr, error);
        }
    };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);

    eprintln!(
        "csp headers: {:#?}",
        response.headers().get("content-security-policy")
    );
    assert_ne!(response.headers().get("content-security-policy"), None);

    // here we test the /pkg/ endpoint which shouldn't have the headers
    let response =
        match reqwest::get(format!("{}pkg/external/bootstrap.bundle.min.js", &addr)).await {
            Ok(value) => value,
            Err(error) => {
                panic!("Failed to query {:?} : {:#?}", addr, error);
            }
        };
    eprintln!("response: {:#?}", response);
    assert_eq!(response.status(), 200);
    eprintln!(
        "csp headers: {:#?}",
        response.headers().get("content-security-policy")
    );
    assert_eq!(response.headers().get("content-security-policy"), None);
}
