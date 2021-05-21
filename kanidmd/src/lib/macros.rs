macro_rules! setup_test {
    (
        $au:expr
    ) => {{
        use crate::utils::duration_from_epoch_now;
        use env_logger;

        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        // Create an in memory BE
        let schema_outer = Schema::new($au).expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be = Backend::new($au, BackendConfig::new_test(), idxmeta, false)
            .expect("Failed to init BE");

        let qs = QueryServer::new(be, schema_outer);
        qs.initialise_helper($au, duration_from_epoch_now())
            .expect("init failed!");
        qs
    }};
    (
        $au:expr,
        $preload_entries:expr
    ) => {{
        use crate::utils::duration_from_epoch_now;
        use async_std::task;
        use env_logger;

        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        // Create an in memory BE
        let schema_outer = Schema::new($au).expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be = Backend::new($au, BackendConfig::new_test(), idxmeta, false)
            .expect("Failed to init BE");

        let qs = QueryServer::new(be, schema_outer);
        qs.initialise_helper($au, duration_from_epoch_now())
            .expect("init failed!");

        if !$preload_entries.is_empty() {
            let qs_write = task::block_on(qs.write_async(duration_from_epoch_now()));
            qs_write
                .internal_create($au, $preload_entries)
                .expect("Failed to preload entries");
            assert!(qs_write.commit($au).is_ok());
        }
        qs
    }};
}

#[cfg(test)]
macro_rules! run_test_no_init {
    ($test_fn:expr) => {{
        use crate::be::{Backend, BackendConfig};
        use crate::prelude::*;
        use crate::schema::Schema;
        use crate::utils::duration_from_epoch_now;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be = match Backend::new(&mut audit, BackendConfig::new_test(), idxmeta, false) {
            Ok(be) => be,
            Err(e) => {
                audit.write_log();
                error!("{:?}", e);
                panic!()
            }
        };
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
        use crate::be::{Backend, BackendConfig};
        use crate::prelude::*;
        use crate::schema::Schema;
        #[allow(unused_imports)]
        use crate::utils::duration_from_epoch_now;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

        let test_server = setup_test!(&mut audit);

        $test_fn(&test_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        let verifications = test_server.verify(&mut audit, duration_from_epoch_now());
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
        e.set_ava("spn", btreeset![spn]);

        let e = unsafe { e.into_sealed_committed() };

        Account::try_from_entry_no_groups(&e).expect("Account conversion failure")
    }};
}

macro_rules! run_idm_test_inner {
    ($test_fn:expr) => {{
        #[allow(unused_imports)]
        use crate::be::{Backend, BackendConfig};
        #[allow(unused_imports)]
        use crate::idm::server::{IdmServer, IdmServerDelayed};
        use crate::prelude::*;
        #[allow(unused_imports)]
        use crate::schema::Schema;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();

        let mut audit = AuditScope::new("run_test", uuid::Uuid::new_v4(), None);

        let test_server = setup_test!(&mut audit);

        let (test_idm_server, mut idms_delayed) = IdmServer::new(
            &mut audit,
            test_server.clone(),
            "https://idm.example.com".to_string(),
            duration_from_epoch_now(),
        )
        .expect("Failed to setup idms");

        $test_fn(
            &test_server,
            &test_idm_server,
            &mut idms_delayed,
            &mut audit,
        );
        // Any needed teardown?
        // Make sure there are no errors.
        assert!(
            test_server
                .verify(&mut audit, duration_from_epoch_now())
                .len()
                == 0
        );
        idms_delayed.is_empty_or_panic();
        audit
    }};
}

#[cfg(test)]
macro_rules! run_idm_test {
    ($test_fn:expr) => {{
        let audit = run_idm_test_inner!($test_fn);
        audit.write_log();
    }};
}

pub fn run_idm_test_no_logging<F>(mut test_fn: F)
where
    F: FnMut(
        &crate::server::QueryServer,
        &crate::idm::server::IdmServer,
        &crate::idm::server::IdmServerDelayed,
        &mut crate::audit::AuditScope,
    ),
{
    let _ = run_idm_test_inner!(test_fn);
}

// Test helpers for all plugins.
#[cfg(test)]
#[macro_export]
macro_rules! run_create_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $create_entries:ident,
        $internal:expr,
        $check:expr
    ) => {{
        use crate::be::{Backend, BackendConfig};
        use crate::event::CreateEvent;
        use crate::prelude::*;
        use crate::schema::Schema;
        use crate::utils::duration_from_epoch_now;

        let mut au = AuditScope::new("run_create_test", uuid::Uuid::new_v4(), None);
        lperf_segment!(&mut au, "plugins::macros::run_create_test", || {
            let qs = setup_test!(&mut au, $preload_entries);

            let ce = match $internal {
                None => CreateEvent::new_internal($create_entries.clone()),
                Some(e_str) => unsafe {
                    CreateEvent::new_impersonate_entry_ser(e_str, $create_entries.clone())
                },
            };

            {
                let qs_write = qs.write(duration_from_epoch_now());
                let r = qs_write.create(&mut au, &ce);
                debug!("test result: {:?}", r);
                assert!(r == $expect);
                $check(&mut au, &qs_write);
                match r {
                    Ok(_) => {
                        qs_write.commit(&mut au).expect("commit failure!");
                    }
                    Err(e) => {
                        ladmin_error!(&mut au, "Rolling back => {:?}", e);
                    }
                }
            }
            // Make sure there are no errors.
            debug!("starting verification");
            let ver = qs.verify(&mut au, duration_from_epoch_now());
            debug!("verification -> {:?}", ver);
            assert!(ver.len() == 0);
        });
        // Dump the raw audit log.
        au.write_log();
    }};
}

#[cfg(test)]
#[macro_export]
macro_rules! run_modify_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $modify_filter:expr,
        $modify_list:expr,
        $internal:expr,
        $check:expr
    ) => {{
        use crate::be::{Backend, BackendConfig};
        use crate::event::ModifyEvent;
        use crate::prelude::*;
        use crate::schema::Schema;

        let mut au = AuditScope::new("run_modify_test", uuid::Uuid::new_v4(), None);
        lperf_segment!(&mut au, "plugins::macros::run_modify_test", || {
            let qs = setup_test!(&mut au, $preload_entries);

            let me = match $internal {
                None => unsafe { ModifyEvent::new_internal_invalid($modify_filter, $modify_list) },
                Some(e_str) => unsafe {
                    ModifyEvent::new_impersonate_entry_ser(e_str, $modify_filter, $modify_list)
                },
            };

            {
                let qs_write = qs.write(duration_from_epoch_now());
                let r = lperf_segment!(
                    &mut au,
                    "plugins::macros::run_modify_test -> main_test",
                    || { qs_write.modify(&mut au, &me) }
                );
                lperf_segment!(
                    &mut au,
                    "plugins::macros::run_modify_test -> post_test check",
                    || { $check(&mut au, &qs_write) }
                );
                debug!("test result: {:?}", r);
                assert!(r == $expect);
                match r {
                    Ok(_) => {
                        qs_write.commit(&mut au).expect("commit failure!");
                    }
                    Err(e) => {
                        ladmin_error!(&mut au, "Rolling back => {:?}", e);
                    }
                }
            }
            // Make sure there are no errors.
            debug!("starting verification");
            let ver = qs.verify(&mut au, duration_from_epoch_now());
            debug!("verification -> {:?}", ver);
            assert!(ver.len() == 0);
        });
        // Dump the raw audit log.
        au.write_log();
    }};
}

#[cfg(test)]
#[macro_export]
macro_rules! run_delete_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $delete_filter:expr,
        $internal:expr,
        $check:expr
    ) => {{
        use crate::be::{Backend, BackendConfig};
        use crate::event::DeleteEvent;
        use crate::prelude::*;
        use crate::schema::Schema;
        use crate::utils::duration_from_epoch_now;

        let mut au = AuditScope::new("run_delete_test", uuid::Uuid::new_v4(), None);
        lperf_segment!(&mut au, "plugins::macros::run_delete_test", || {
            let qs = setup_test!(&mut au, $preload_entries);

            let de = match $internal {
                Some(e_str) => unsafe {
                    DeleteEvent::new_impersonate_entry_ser(e_str, $delete_filter.clone())
                },
                None => unsafe { DeleteEvent::new_internal_invalid($delete_filter.clone()) },
            };

            {
                let qs_write = qs.write(duration_from_epoch_now());
                let r = qs_write.delete(&mut au, &de);
                debug!("test result: {:?}", r);
                $check(&mut au, &qs_write);
                assert!(r == $expect);
                match r {
                    Ok(_) => {
                        qs_write.commit(&mut au).expect("commit failure!");
                    }
                    Err(e) => {
                        ladmin_error!(&mut au, "Rolling back => {:?}", e);
                    }
                }
            }
            // Make sure there are no errors.
            debug!("starting verification");
            let ver = qs.verify(&mut au, duration_from_epoch_now());
            debug!("verification -> {:?}", ver);
            assert!(ver.len() == 0);
        });
        // Dump the raw audit log.
        au.write_log();
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
macro_rules! f_inc {
    (
        $vs:expr
    ) => {{
        use crate::filter::FC;
        let s: Box<[FC]> = Box::new($vs);
        f_inc(s.into_vec())
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
            f_and, f_andnot, f_eq, f_id, f_inc, f_lt, f_or, f_pres, f_self, f_spn_name, f_sub,
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
        use crate::filter::{
            f_and, f_andnot, f_eq, f_id, f_inc, f_lt, f_or, f_pres, f_self, f_sub,
        };
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
        use crate::filter::{
            f_and, f_andnot, f_eq, f_id, f_inc, f_lt, f_or, f_pres, f_self, f_sub,
        };
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
        use crate::filter::{f_and, f_andnot, f_eq, f_inc, f_lt, f_or, f_pres, f_sub};
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
        use crate::filter::{f_and, f_andnot, f_eq, f_inc, f_lt, f_or, f_pres, f_sub};
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

#[allow(unused_macros)]
#[macro_export]
macro_rules! entry_init {
    () => ({
        let e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1
    });
    ($ava:expr) => ({
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava($ava.0, $ava.1);
        e1
    });
    ($ava:expr, $($item:expr),*) => ({
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava($ava.0, $ava.1);
        $(e1.add_ava($item.0, $item.1);)*
        e1
    });
}
