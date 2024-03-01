use crate::be::{Backend, BackendConfig};
use crate::prelude::*;
use crate::schema::Schema;

pub struct TestConfiguration {
    pub domain_level: DomainVersion,
}

impl Default for TestConfiguration {
    fn default() -> Self {
        TestConfiguration {
            domain_level: DOMAIN_TGT_LEVEL,
        }
    }
}

#[allow(clippy::expect_used)]
pub async fn setup_test(config: TestConfiguration) -> QueryServer {
    sketching::test_init();

    // Create an in memory BE
    let schema_outer = Schema::new().expect("Failed to init schema");
    let idxmeta = {
        let schema_txn = schema_outer.write();
        schema_txn.reload_idxmeta()
    };
    let be =
        Backend::new(BackendConfig::new_test("main"), idxmeta, false).expect("Failed to init BE");

    let test_server = QueryServer::new(be, schema_outer, "example.com".to_string(), Duration::ZERO)
        .expect("Failed to setup Query Server");

    test_server
        .initialise_helper(duration_from_epoch_now(), config.domain_level)
        .await
        .expect("init failed!");

    test_server
}

#[allow(clippy::expect_used)]
pub async fn setup_pair_test(config: TestConfiguration) -> (QueryServer, QueryServer) {
    sketching::test_init();

    let qs_a = {
        // Create an in memory BE
        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write();
            schema_txn.reload_idxmeta()
        };
        let be = Backend::new(BackendConfig::new_test("db_a"), idxmeta, false)
            .expect("Failed to init BE");

        // Init is called via the proc macro
        QueryServer::new(be, schema_outer, "example.com".to_string(), Duration::ZERO)
            .expect("Failed to setup Query Server")
    };

    let qs_b = {
        // Create an in memory BE
        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write();
            schema_txn.reload_idxmeta()
        };
        let be = Backend::new(BackendConfig::new_test("db_b"), idxmeta, false)
            .expect("Failed to init BE");

        // Init is called via the proc macro
        QueryServer::new(be, schema_outer, "example.com".to_string(), Duration::ZERO)
            .expect("Failed to setup Query Server")
    };

    qs_a.initialise_helper(duration_from_epoch_now(), config.domain_level)
        .await
        .expect("init failed!");

    qs_b.initialise_helper(duration_from_epoch_now(), config.domain_level)
        .await
        .expect("init failed!");

    (qs_a, qs_b)
}

#[allow(clippy::expect_used)]
pub async fn setup_idm_test(
    config: TestConfiguration,
) -> (IdmServer, IdmServerDelayed, IdmServerAudit) {
    let qs = setup_test(config).await;

    IdmServer::new(qs, "https://idm.example.com")
        .await
        .expect("Failed to setup idms")
}
