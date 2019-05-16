
macro_rules! run_test {
    ($test_fn:expr) => {{

        use crate::audit::AuditScope;
        use crate::server::QueryServer;
        use crate::be::Backend;
        use crate::schema::Schema;
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
        let test_server = QueryServer::new(be, Arc::new(schema_outer));

        $test_fn(&test_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        assert!(test_server.verify(&mut audit).len() == 0);
    }};
}
