#[cfg(test)]
macro_rules! entry_str_to_account {
    ($entry_str:expr) => {{
        use crate::entry::{Entry, EntryNew, EntryValid};
        use crate::idm::account::Account;

        let e: Entry<EntryValid, EntryNew> =
            unsafe { Entry::unsafe_from_entry_str($entry_str).to_valid_new() };
        let e = unsafe { e.to_valid_committed() };

        Account::try_from_entry(e).expect("Account conversion failure")
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

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,rsidm=debug");
        let _ = env_logger::builder().is_test(true).try_init();

        let mut audit = AuditScope::new("run_test");

        let be = Backend::new(&mut audit, "", 1).expect("Failed to init be");
        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");

        let test_server = QueryServer::new(be, schema_outer);
        test_server
            .initialise_helper(&mut audit)
            .expect("init failed");

        let test_idm_server = IdmServer::new(test_server.clone());

        $test_fn(&test_server, &test_idm_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        assert!(test_server.verify(&mut audit).len() == 0);
    }};
}
