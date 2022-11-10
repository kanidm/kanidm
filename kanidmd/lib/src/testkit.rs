use crate::be::{Backend, BackendConfig};
use crate::prelude::*;
use crate::schema::Schema;
#[allow(unused_imports)]
use crate::utils::duration_from_epoch_now;

#[allow(clippy::expect_used)]
pub async fn setup_test() -> QueryServer {
    sketching::test_init();

    // Create an in memory BE
    let schema_outer = Schema::new().expect("Failed to init schema");
    let idxmeta = {
        let schema_txn = schema_outer.write();
        schema_txn.reload_idxmeta()
    };
    let be = Backend::new(BackendConfig::new_test(), idxmeta, false).expect("Failed to init BE");

    // Init is called via the proc macro
    QueryServer::new(be, schema_outer, "example.com".to_string())
}

#[allow(clippy::expect_used)]
pub async fn setup_idm_test() -> (IdmServer, IdmServerDelayed) {
    let qs = setup_test().await;

    qs.initialise_helper(duration_from_epoch_now())
        .await
        .expect("init failed!");
    IdmServer::new(qs, "https://idm.example.com").expect("Failed to setup idms")
}
