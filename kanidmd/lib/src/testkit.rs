use crate::be::{Backend, BackendConfig};
use crate::prelude::*;
use crate::schema::Schema;
#[allow(unused_imports)]
use crate::utils::duration_from_epoch_now;

pub async fn setup_test() -> QueryServer {
    let _ = sketching::test_init();

    // Create an in memory BE
    let schema_outer = Schema::new().expect("Failed to init schema");
    let idxmeta = {
        let schema_txn = schema_outer.write();
        schema_txn.reload_idxmeta()
    };
    let be = Backend::new(BackendConfig::new_test(), idxmeta, false).expect("Failed to init BE");

    let qs = QueryServer::new(be, schema_outer, "example.com".to_string());
    // Init is called via the proc macro
    qs
}
