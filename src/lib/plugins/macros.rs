// #[macro_escape]

macro_rules! setup_test {
    (
        $au:expr,
        $preload_entries:ident
    ) => {{
        // Create an in memory BE
        let be = Backend::new($au, "").unwrap();

        let schema_outer = Schema::new($au).unwrap();
        {
            let mut schema = schema_outer.write();
            schema.bootstrap_core($au).unwrap();
            schema.commit().unwrap();
        }
        let qs = QueryServer::new(be, Arc::new(schema_outer));

        if !$preload_entries.is_empty() {
            let qs_write = qs.write();
            qs_write.internal_create($au, $preload_entries).unwrap();
            assert!(qs_write.commit($au).is_ok());
        }
        qs
    }};
}

// Test helpers for all plugins.
#[macro_export]
macro_rules! run_create_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $create_entries:ident,
        $internal:ident,
        $check:expr
    ) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::event::CreateEvent;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use std::sync::Arc;

        let mut au = AuditScope::new("run_create_test");
        audit_segment!(au, || {
            let qs = setup_test!(&mut au, $preload_entries);

            let ce = if $internal {
                CreateEvent::new_internal($create_entries.clone())
            } else {
                CreateEvent::from_vec($create_entries.clone())
            };

            let mut au_test = AuditScope::new("create_test");
            {
                let qs_write = qs.write();
                let r = qs_write.create(&mut au_test, &ce);
                assert!(r == $expect);
                $check(&mut au_test, &qs_write);
                r.map(|_| {
                    assert!(qs_write.commit(&mut au_test).is_ok());
                });
            }
            // Make sure there are no errors.
            assert!(qs.verify(&mut au_test).len() == 0);

            au.append_scope(au_test);
        });
        // Dump the raw audit log.
        println!("{}", au);
    }};
}

#[macro_export]
macro_rules! run_modify_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $modify_filter:expr,
        $modify_list:expr,
        $internal:ident,
        $check:expr
    ) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::event::ModifyEvent;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use std::sync::Arc;

        let mut au = AuditScope::new("run_modify_test");
        audit_segment!(au, || {
            let qs = setup_test!(&mut au, $preload_entries);

            let me = if $internal {
                ModifyEvent::new_internal($modify_filter, $modify_list)
            } else {
                ModifyEvent::from_filter($modify_filter, $modify_list)
            };

            let mut au_test = AuditScope::new("modify_test");
            {
                let qs_write = qs.write();
                let r = qs_write.modify(&mut au_test, &me);
                $check(&mut au_test, &qs_write);
                assert!(r == $expect);
                r.map(|_| {
                    assert!(qs_write.commit(&mut au_test).is_ok());
                });
            }
            // Make sure there are no errors.
            assert!(qs.verify(&mut au_test).len() == 0);

            au.append_scope(au_test);
        });
        // Dump the raw audit log.
        println!("{}", au);
    }};
}

#[macro_export]
macro_rules! run_delete_test {
    (
        $expect:expr,
        $preload_entries:ident,
        $delete_filter:expr,
        $internal:ident,
        $check:expr
    ) => {{
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::event::DeleteEvent;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use std::sync::Arc;

        let mut au = AuditScope::new("run_delete_test");
        audit_segment!(au, || {
            let qs = setup_test!(&mut au, $preload_entries);

            let de = if $internal {
                DeleteEvent::new_internal($delete_filter.clone())
            } else {
                DeleteEvent::from_filter($delete_filter.clone())
            };

            let mut au_test = AuditScope::new("delete_test");
            {
                let qs_write = qs.write();
                let r = qs_write.delete(&mut au_test, &de);
                $check(&mut au_test, &qs_write);
                assert!(r == $expect);
                r.map(|_| {
                    assert!(qs_write.commit(&mut au_test).is_ok());
                });
            }
            // Make sure there are no errors.
            assert!(qs.verify(&mut au_test).len() == 0);

            au.append_scope(au_test);
        });
        // Dump the raw audit log.
        println!("{}", au);
    }};
}
