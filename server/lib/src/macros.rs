#[cfg(test)]
macro_rules! setup_test {
    () => {{
        let _ = sketching::test_init();

        // Create an in memory BE
        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write_blocking();
            schema_txn.reload_idxmeta()
        };
        let be = Backend::new(BackendConfig::new_test("main"), idxmeta, false)
            .expect("Failed to init BE");

        let qs = QueryServer::new(be, schema_outer, "example.com".to_string())
            .expect("Failed to setup Query Server");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(qs.initialise_helper(duration_from_epoch_now()))
            .expect("init failed!");
        qs
    }};
    (
        $preload_entries:expr
    ) => {{
        use crate::prelude::duration_from_epoch_now;

        let _ = sketching::test_init();

        // Create an in memory BE
        let schema_outer = Schema::new().expect("Failed to init schema");
        let idxmeta = {
            let schema_txn = schema_outer.write();
            schema_txn.reload_idxmeta()
        };
        let be = Backend::new(BackendConfig::new_test("main"), idxmeta, false)
            .expect("Failed to init BE");

        let qs = QueryServer::new(be, schema_outer, "example.com".to_string())
            .expect("Failed to setup Query Server");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(qs.initialise_helper(duration_from_epoch_now()))
            .expect("init failed!");

        if !$preload_entries.is_empty() {
            let mut qs_write = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(qs.write(duration_from_epoch_now()));
            qs_write
                .internal_create($preload_entries)
                .expect("Failed to preload entries");
            assert!(qs_write.commit().is_ok());
        }
        qs
    }};
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

        let qs = setup_test!($preload_entries);

        let ce = match $internal {
            None => CreateEvent::new_internal($create_entries.clone()),
            Some(ent) => CreateEvent::new_impersonate_identity(
                Identity::from_impersonate_entry_readwrite(ent),
                $create_entries.clone(),
            ),
        };

        {
            let mut qs_write = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(qs.write(duration_from_epoch_now()));
            let r = qs_write.create(&ce);
            trace!("test result: {:?}", r);
            assert!(r == $expect);
            $check(&mut qs_write);
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
        let ver = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(qs.verify());
        trace!("verification -> {:?}", ver);
        assert!(ver.len() == 0);
    }};
}

#[cfg(test)]
/// Runs a test with preloaded entries, then modifies based on a filter/list, then runs a given check
macro_rules! run_modify_test {
    (
        // expected outcome
        $expect:expr,
        // things to preload
        $preload_entries:ident,
        // the targets to modify
        $modify_filter:expr,
        // changes to make
        $modify_list:expr,
        $internal:expr,
        // something to run after the preload but before the modification, takes `&mut qs_write`
        $pre_hook:expr,
        // the result we expect
        $check:expr
    ) => {{
        use crate::be::{Backend, BackendConfig};
        use crate::event::ModifyEvent;
        use crate::prelude::*;
        use crate::schema::Schema;

        let qs = setup_test!($preload_entries);

        {
            let mut qs_write = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(qs.write(duration_from_epoch_now()));
            $pre_hook(&mut qs_write);
            qs_write.commit().expect("commit failure!");
        }

        let me = match $internal {
            None => ModifyEvent::new_internal_invalid($modify_filter, $modify_list),
            Some(ent) => ModifyEvent::new_impersonate_entry(ent, $modify_filter, $modify_list),
        };

        {
            let mut qs_write = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(qs.write(duration_from_epoch_now()));
            let r = qs_write.modify(&me);
            $check(&mut qs_write);
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
        let ver = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(qs.verify());
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

        let qs = setup_test!($preload_entries);

        let de = match $internal {
            Some(ent) => DeleteEvent::new_impersonate_entry(ent, $delete_filter.clone()),
            None => DeleteEvent::new_internal_invalid($delete_filter.clone()),
        };

        {
            let mut qs_write = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(qs.write(duration_from_epoch_now()));
            let r = qs_write.delete(&de);
            trace!("test result: {:?}", r);
            $check(&mut qs_write);
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
        let ver = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(qs.verify());
        trace!("verification -> {:?}", ver);
        assert!(ver.len() == 0);
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

#[macro_export]
/// Build a filter which matches class == input
macro_rules! match_class_filter {
    ($class:expr) => {
        ProtoFilter::Eq(Attribute::Class.to_string(), $class.to_string())
    };
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
            // I think to be consistent, we need the content of b to always
            // the content of a
            // if !$a.contains_key(k) {
            $a.insert(k.clone(), v.clone());
            // }
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
/// Takes EntryClass objects and makes  a VaueSetIutf8
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

macro_rules! limmediate_warning {
    ($($arg:tt)*) => ({
        eprint!($($arg)*)
    })
}
