#[cfg(test)]
macro_rules! run_test_no_init {
    ($test_fn:expr) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use crate::utils::duration_from_epoch_now;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

        let be = match Backend::new(&mut audit, "", 1) {
            Ok(be) => be,
            Err(e) => {
                audit.write_log();
                error!("{:?}", e);
                panic!()
            }
        };
        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");
        let test_server = QueryServer::new(be, schema_outer);

        $test_fn(&test_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        // let verifications = test_server.verify(&mut audit);
        // ltrace!(audit, "Verification result: {:?}", verifications);
        // assert!(verifications.len() == 0);
        audit.write_log();
    }};
}

#[cfg(test)]
macro_rules! run_test {
    ($test_fn:expr) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use crate::utils::duration_from_epoch_now;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

        let be = match Backend::new(&mut audit, "", 1) {
            Ok(be) => be,
            Err(e) => {
                audit.write_log();
                error!("{:?}", e);
                panic!()
            }
        };
        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");
        let test_server = QueryServer::new(be, schema_outer);

        test_server
            .initialise_helper(&mut audit, duration_from_epoch_now())
            .expect("init failed!");

        $test_fn(&test_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        let verifications = test_server.verify(&mut audit);
        ltrace!(audit, "Verification result: {:?}", verifications);
        assert!(verifications.len() == 0);
        audit.write_log();
    }};
}

#[cfg(test)]
macro_rules! entry_str_to_account {
    ($entry_str:expr) => {{
        use crate::entry::{Entry, EntryInvalid, EntryNew};
        use crate::idm::account::Account;
        use crate::value::Value;

        let mut e: Entry<EntryInvalid, EntryNew> =
            unsafe { Entry::unsafe_from_entry_str($entry_str).into_invalid_new() };
        // Add spn, because normally this is generated but in tests we can't.
        let spn = e
            .get_ava_single_str("name")
            .map(|s| Value::new_spn_str(s, "example.com"))
            .expect("Failed to munge spn from name!");
        e.set_avas("spn", vec![spn]);

        let e = unsafe { e.into_sealed_committed() };

        Account::try_from_entry_no_groups(e).expect("Account conversion failure")
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
        use crate::utils::duration_from_epoch_now;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

        let be = Backend::new(&mut audit, "", 1).expect("Failed to init be");
        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");

        let test_server = QueryServer::new(be, schema_outer);
        test_server
            .initialise_helper(&mut audit, duration_from_epoch_now())
            .expect("init failed");

        let test_idm_server = IdmServer::new(test_server.clone());

        $test_fn(&test_server, &test_idm_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        assert!(test_server.verify(&mut audit).len() == 0);
        audit.write_log();
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! modlist {
    (
        $vs:expr
    ) => {{
        #[allow(unused_imports)]
        use crate::modify::{m_pres, m_purge, m_remove};
        use crate::modify::{Modify, ModifyList};
        let s: Box<[Modify]> = Box::new($vs);
        ModifyList::new_list(s.into_vec())
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! f_and {
    (
        $vs:expr
    ) => {{
        use crate::filter::FC;
        let s: Box<[FC]> = Box::new($vs);
        f_and(s.into_vec())
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! f_or {
    (
        $vs:expr
    ) => {{
        use crate::filter::FC;
        let s: Box<[FC]> = Box::new($vs);
        f_or(s.into_vec())
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! filter {
    (
        $fc:expr
    ) => {{
        use crate::filter::Filter;
        #[allow(unused_imports)]
        use crate::filter::FC;
        #[allow(unused_imports)]
        use crate::filter::{
            f_and, f_andnot, f_eq, f_id, f_lt, f_or, f_pres, f_self, f_spn_name, f_sub,
        };
        Filter::new_ignore_hidden($fc)
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! filter_rec {
    (
        $fc:expr
    ) => {{
        use crate::filter::Filter;
        #[allow(unused_imports)]
        use crate::filter::FC;
        #[allow(unused_imports)]
        use crate::filter::{f_and, f_andnot, f_eq, f_id, f_lt, f_or, f_pres, f_self, f_sub};
        Filter::new_recycled($fc)
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! filter_all {
    (
        $fc:expr
    ) => {{
        use crate::filter::Filter;
        #[allow(unused_imports)]
        use crate::filter::FC;
        #[allow(unused_imports)]
        use crate::filter::{f_and, f_andnot, f_eq, f_id, f_lt, f_or, f_pres, f_self, f_sub};
        Filter::new($fc)
    }};
}

#[cfg(test)]
#[allow(unused_macros)]
#[macro_export]
macro_rules! filter_valid {
    (
        $fc:expr
    ) => {{
        #[allow(unused_imports)]
        use crate::filter::{f_and, f_andnot, f_eq, f_lt, f_or, f_pres, f_sub};
        use crate::filter::{Filter, FilterInvalid};
        let f: Filter<FilterInvalid> = Filter::new($fc);
        // Create a resolved filter, via the most unsafe means possible!
        f.into_valid()
    }};
}

#[cfg(test)]
#[allow(unused_macros)]
#[macro_export]
macro_rules! filter_resolved {
    (
        $fc:expr
    ) => {{
        #[allow(unused_imports)]
        use crate::filter::{f_and, f_andnot, f_eq, f_lt, f_or, f_pres, f_sub};
        use crate::filter::{Filter, FilterInvalid};
        let f: Filter<FilterInvalid> = Filter::new($fc);
        // Create a resolved filter, via the most unsafe means possible!
        f.into_valid_resolved()
    }};
}

#[cfg(test)]
#[allow(unused_macros)]
#[macro_export]
macro_rules! pvalue_utf8 {
    (
        $v:expr
    ) => {{
        use crate::value::PartialValue;
        PartialValue::new_utf8(v.to_string())
    }};
}

#[cfg(test)]
#[allow(unused_macros)]
#[macro_export]
macro_rules! pvalue_iutf8 {
    (
        $v:expr
    ) => {{
        use crate::value::PartialValue;
        PartialValue::new_iutf8(v.to_string())
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! btreeset {
    () => (
        compile_error!("BTreeSet needs at least 1 element")
    );
    ($e:expr) => ({
        use std::collections::BTreeSet;
        let mut x: BTreeSet<_> = BTreeSet::new();
        assert!(x.insert($e));
        x
    });
    ($e:expr,) => ({
        use std::collections::BTreeSet;
        let mut x: BTreeSet<_> = BTreeSet::new();
        assert!(x.insert($e));
        x
    });
    ($e:expr, $($item:expr),*) => ({
        use std::collections::BTreeSet;
        let mut x: BTreeSet<_> = BTreeSet::new();
        assert!(x.insert($e));
        $(assert!(x.insert($item));)*
        x
    });
}
