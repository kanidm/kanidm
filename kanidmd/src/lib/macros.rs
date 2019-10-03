#[cfg(test)]
macro_rules! run_test {
    ($test_fn:expr) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::schema::Schema;
        use crate::server::QueryServer;

        use env_logger;
        ::std::env::set_var("RUST_LOG", "actix_web=debug,kanidm=debug");
        let _ = env_logger::builder().is_test(true).try_init();

        let mut audit = AuditScope::new("run_test");

        let be = match Backend::new(&mut audit, "", 1) {
            Ok(be) => be,
            Err(e) => {
                debug!("{}", audit);
                error!("{:?}", e);
                panic!()
            }
        };
        let schema_outer = Schema::new(&mut audit).expect("Failed to init schema");
        let test_server = QueryServer::new(be, schema_outer);

        test_server
            .initialise_helper(&mut audit)
            .expect("init failed!");

        $test_fn(&test_server, &mut audit);
        // Any needed teardown?
        // Make sure there are no errors.
        let verifications = test_server.verify(&mut audit);
        audit_log!(audit, "Verification result: {:?}", verifications);
        assert!(verifications.len() == 0);
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
        use crate::filter::{f_and, f_andnot, f_eq, f_or, f_pres, f_self, f_sub, f_id};
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
        use crate::filter::{f_and, f_andnot, f_eq, f_or, f_pres, f_self, f_sub, f_id};
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
        use crate::filter::{f_and, f_andnot, f_eq, f_or, f_pres, f_self, f_sub, f_id};
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
        use crate::filter::{f_and, f_andnot, f_eq, f_or, f_pres, f_sub};
        use crate::filter::{Filter, FilterInvalid};
        let f: Filter<FilterInvalid> = Filter::new($fc);
        // Create a resolved filter, via the most unsafe means possible!
        f.to_valid()
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
        use crate::filter::{f_and, f_andnot, f_eq, f_or, f_pres, f_sub};
        use crate::filter::{Filter, FilterInvalid};
        let f: Filter<FilterInvalid> = Filter::new($fc);
        // Create a resolved filter, via the most unsafe means possible!
        f.to_valid_resolved()
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
