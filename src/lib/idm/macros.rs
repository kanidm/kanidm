#[cfg(test)]
macro_rules! entry_str_to_account {
    ($entry_str:expr) => {{
        use crate::entry::{Entry, EntryNew, EntryValid};
        use crate::idm::account::Account;

        let e: Entry<EntryValid, EntryNew> =
            serde_json::from_str($entry_str).expect("Json deserialise failure!");
        let e = unsafe { e.to_valid_committed() };

        Account::try_from(e).expect("Account conversion failure")
    }};
}

#[cfg(test)]
macro_rules! run_idm_test {
    ($test_fn:expr) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::idm::server::IdmServer;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use std::sync::Arc;

        let mut audit = AuditScope::new("run_test");

        let be = Backend::new(&mut audit, "").expect("Failed to init be");
        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");
        {
            let mut schema = schema_outer.write();
            schema
                .bootstrap_core(&mut audit)
                .expect("Failed to bootstrap schema");
            schema.commit().expect("Failed to commit schema");
        }

        let test_server = QueryServer::new(be, schema_outer);

        {
            let ts_write = test_server.write();
            ts_write.initialise(&mut audit).expect("Init failed!");
            ts_write.commit(&mut audit).expect("Commit failed!");
        }

        let test_idm_server = IdmServer::new(test_server.clone());

        $test_fn(&test_server, &test_idm_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        assert!(test_server.verify(&mut audit).len() == 0);
    }};
}
