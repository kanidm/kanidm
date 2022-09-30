macro_rules! setup_test {
    () => {{
        let _ = sketching::test_init();

        // Create an in memory BE
        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be =
            Backend::new(BackendConfig::new_test(), idxmeta, false).expect("Failed to init BE");

        let qs = QueryServer::new(be, schema_outer, "example.com".to_string());
        qs.initialise_helper(duration_from_epoch_now())
            .expect("init failed!");
        qs
    }};
    (
        $preload_entries:expr
    ) => {{
        use async_std::task;

        use crate::utils::duration_from_epoch_now;

        let _ = sketching::test_init();

        // Create an in memory BE
        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be =
            Backend::new(BackendConfig::new_test(), idxmeta, false).expect("Failed to init BE");

        let qs = QueryServer::new(be, schema_outer, "example.com".to_string());
        qs.initialise_helper(duration_from_epoch_now())
            .expect("init failed!");

        if !$preload_entries.is_empty() {
            let qs_write = task::block_on(qs.write_async(duration_from_epoch_now()));
            qs_write
                .internal_create($preload_entries)
                .expect("Failed to preload entries");
            assert!(qs_write.commit().is_ok());
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

        let _ = sketching::test_init();

        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be = match Backend::new(BackendConfig::new_test(), idxmeta, false) {
            Ok(be) => be,
            Err(e) => {
                error!("{:?}", e);
                panic!()
            }
        };
        let test_server = QueryServer::new(be, schema_outer, "example.com".to_string());

        $test_fn(&test_server);
        // Any needed teardown?
        // Make sure there are no errors.
        // let verifications = test_server.verify();
        // assert!(verifications.len() == 0);
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

        let _ = sketching::test_init();

        let test_server = setup_test!();

        $test_fn(&test_server);
        // Any needed teardown?
        // Make sure there are no errors.
        let verifications = test_server.verify();
        trace!("Verification result: {:?}", verifications);
        assert!(verifications.len() == 0);
    }};
}

#[cfg(test)]
macro_rules! entry_str_to_account {
    ($entry_str:expr) => {{
        use std::iter::once;

        use crate::entry::{Entry, EntryInvalid, EntryNew};
        use crate::idm::account::Account;
        use crate::value::Value;

        let mut e: Entry<EntryInvalid, EntryNew> =
            unsafe { Entry::unsafe_from_entry_str($entry_str).into_invalid_new() };
        // Add spn, because normally this is generated but in tests we can't.
        let spn = e
            .get_ava_single_iname("name")
            .map(|s| Value::new_spn_str(s, "example.com"))
            .expect("Failed to munge spn from name!");
        e.set_ava("spn", once(spn));

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
        /*
        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder()
            .format_timestamp(None)
            .format_level(false)
            .is_test(true)
            .try_init();
        */

        let test_server = setup_test!();

        let (test_idm_server, mut idms_delayed) =
            IdmServer::new(test_server.clone(), "https://idm.example.com")
                .expect("Failed to setup idms");

        $test_fn(&test_server, &test_idm_server, &mut idms_delayed);
        // Any needed teardown?
        // Make sure there are no errors.
        assert!(test_server.verify().len() == 0);
        idms_delayed.check_is_empty_or_panic();
    }};
}

#[cfg(test)]
macro_rules! run_idm_test {
    ($test_fn:expr) => {{
        let _ = sketching::test_init();
        run_idm_test_inner!($test_fn);
    }};
}

pub fn run_idm_test_no_logging<F>(mut test_fn: F)
where
    F: FnMut(
        &crate::server::QueryServer,
        &crate::idm::server::IdmServer,
        &crate::idm::server::IdmServerDelayed,
    ),
{
    let _ = sketching::test_init();
    let _ = run_idm_test_inner!(test_fn);
}

// Test helpers for all plugins.
// #[macro_export]
#[cfg(test)]
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

        let qs = setup_test!($preload_entries);

        let ce = match $internal {
            None => CreateEvent::new_internal($create_entries.clone()),
            Some(e_str) => unsafe {
                CreateEvent::new_impersonate_entry_ser(e_str, $create_entries.clone())
            },
        };

        {
            let qs_write = qs.write(duration_from_epoch_now());
            let r = qs_write.create(&ce);
            trace!("test result: {:?}", r);
            assert!(r == $expect);
            $check(&qs_write);
            match r {
                Ok(_) => {
                    qs_write.commit().expect("commit failure!");
                }
                Err(e) => {
                    admin_error!("Rolling back => {:?}", e);
                }
            }
        }
        // Make sure there are no errors.
        trace!("starting verification");
        let ver = qs.verify();
        trace!("verification -> {:?}", ver);
        assert!(ver.len() == 0);
    }};
}

// #[macro_export]
#[cfg(test)]
macro_rules! run_modify_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $modify_filter:expr,
        $modify_list:expr,
        $internal:expr,
        $pre_hook:expr,
        $check:expr
    ) => {{
        use crate::be::{Backend, BackendConfig};
        use crate::event::ModifyEvent;
        use crate::prelude::*;
        use crate::schema::Schema;

        let qs = setup_test!($preload_entries);

        {
            let qs_write = qs.write(duration_from_epoch_now());
            $pre_hook(&qs_write);
            qs_write.commit().expect("commit failure!");
        }

        let me = match $internal {
            None => unsafe { ModifyEvent::new_internal_invalid($modify_filter, $modify_list) },
            Some(e_str) => unsafe {
                ModifyEvent::new_impersonate_entry_ser(e_str, $modify_filter, $modify_list)
            },
        };

        {
            let qs_write = qs.write(duration_from_epoch_now());
            let r = qs_write.modify(&me);
            $check(&qs_write);
            trace!("test result: {:?}", r);
            assert!(r == $expect);
            match r {
                Ok(_) => {
                    qs_write.commit().expect("commit failure!");
                }
                Err(e) => {
                    admin_error!("Rolling back => {:?}", e);
                }
            }
        }
        // Make sure there are no errors.
        trace!("starting verification");
        let ver = qs.verify();
        trace!("verification -> {:?}", ver);
        assert!(ver.len() == 0);
    }};
}

// #[macro_export]
#[cfg(test)]
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

        let qs = setup_test!($preload_entries);

        let de = match $internal {
            Some(e_str) => unsafe {
                DeleteEvent::new_impersonate_entry_ser(e_str, $delete_filter.clone())
            },
            None => unsafe { DeleteEvent::new_internal_invalid($delete_filter.clone()) },
        };

        {
            let qs_write = qs.write(duration_from_epoch_now());
            let r = qs_write.delete(&de);
            trace!("test result: {:?}", r);
            $check(&qs_write);
            assert!(r == $expect);
            match r {
                Ok(_) => {
                    qs_write.commit().expect("commit failure!");
                }
                Err(e) => {
                    admin_error!("Rolling back => {:?}", e);
                }
            }
        }
        // Make sure there are no errors.
        trace!("starting verification");
        let ver = qs.verify();
        trace!("verification -> {:?}", ver);
        assert!(ver.len() == 0);
    }};
}

#[cfg(test)]
macro_rules! run_entrychangelog_test {
    ($test_fn:expr) => {{
        let _ = sketching::test_init();
        let schema_outer = Schema::new().expect("Failed to init schema");

        let schema_txn = schema_outer.read();

        $test_fn(&schema_txn)
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! modlist {
    (
        $vs:expr
    ) => {{
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
        Filter::new_ignore_hidden($fc)
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! filter_rec {
    (
        $fc:expr
    ) => {{
        Filter::new_recycled($fc)
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! filter_all {
    (
        $fc:expr
    ) => {{
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
        btreeset!($e)
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
macro_rules! smolset {
    () => (
        compile_error!("SmolSet needs at least 1 element")
    );
    ($e:expr) => ({
        use smolset::SmolSet;
        let mut x: SmolSet<_> = SmolSet::new();
        assert!(x.insert($e));
        x
    });
    ($e:expr,) => ({
        smolset!($e)
    });
    ($e:expr, $($item:expr),*) => ({
        use smolset::SmolSet;
        let mut x: SmolSet<_> = SmolSet::new();
        assert!(x.insert($e));
        $(assert!(x.insert($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! btreemap {
    () => (
        compile_error!("BTreeSet needs at least 1 element")
    );
    ($e:expr) => ({
        use std::collections::BTreeMap;
        let mut x: BTreeMap<_, _> = BTreeMap::new();
        let (a, b) = $e;
        x.insert(a, b);
        x
    });
    ($e:expr,) => ({
        btreemap!($e)
    });
    ($e:expr, $($item:expr),*) => ({
        use std::collections::BTreeMap;
        let mut x: BTreeMap<_, _> = BTreeMap::new();
        let (a, b) = $e;
        x.insert(a, b);
        $(
            let (a, b) = $item;
            x.insert(a, b);
        )*
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

#[allow(unused_macros)]
#[macro_export]
macro_rules! mergesets {
    (
        $a:expr,
        $b:expr
    ) => {{
        $b.iter().for_each(|v| {
            $a.insert(v.clone());
        });
        Ok(())
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! mergemaps {
    (
        $a:expr,
        $b:expr
    ) => {{
        $b.iter().for_each(|(k, v)| {
            if !$a.contains_key(k) {
                $a.insert(k.clone(), v.clone());
            }
        });
        Ok(())
    }};
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_utf8 {
    () => (
        compile_error!("ValueSetUtf8 needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetUtf8::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetUtf8::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_iutf8 {
    () => (
        compile_error!("ValueSetIutf8 needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetIutf8::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetIutf8::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_iname {
    () => (
        compile_error!("ValueSetIname needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetIname::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetIname::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_uuid {
    () => (
        compile_error!("ValueSetUuid needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetUuid::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetUuid::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_refer {
    () => (
        compile_error!("ValueSetRefer needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetRefer::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetRefer::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_bool {
    () => (
        compile_error!("ValueSetBool needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetBool::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetBool::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_syntax {
    () => (
        compile_error!("ValueSetSyntax needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetSyntax::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetSyntax::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_index {
    () => (
        compile_error!("ValueSetIndex needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetIndex::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetIndex::new($e);
        $(assert!(x.push($item));)*
        x
    });
}

#[allow(unused_macros)]
#[macro_export]
macro_rules! vs_cid {
    () => (
        compile_error!("ValueSetCid needs at least 1 element")
    );
    ($e:expr) => ({
        ValueSetCid::new($e)
    });
    ($e:expr, $($item:expr),*) => ({
        let mut x = ValueSetCid::new($e);
        $(assert!(x.push($item));)*
        x
    });
}
