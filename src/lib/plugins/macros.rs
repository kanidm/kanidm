#[macro_escape]
// Test helpers for all plugins.
#[macro_export]
macro_rules! run_pre_create_test {
    (
            $preload_entries:ident,
            $create_entries:ident,
            $ident:ident,
            $internal:ident,
            $test_fn:expr
        ) => {{
        let mut au = AuditScope::new("run_pre_create_test");
        audit_segment!(au, || {
            // Create an in memory BE
            let be = Backend::new(&mut au, "").unwrap();

            let schema_outer = Schema::new(&mut au).unwrap();
            {
                let mut schema = schema_outer.write();
                schema.bootstrap_core(&mut au).unwrap();
                schema.commit().unwrap();
            }
            let qs = QueryServer::new(be, Arc::new(schema_outer));

            if !$preload_entries.is_empty() {
                let qs_write = qs.write();
                qs_write.internal_create(&mut au, $preload_entries);
                assert!(qs_write.commit(&mut au).is_ok());
            }

            let ce = CreateEvent::from_vec($create_entries.clone());

            let mut au_test = AuditScope::new("pre_create_test");
            {
                let qs_write = qs.write();
                audit_segment!(au_test, || $test_fn(
                    &mut au_test,
                    &qs_write,
                    &mut $create_entries,
                    &ce,
                ));
                assert!(qs_write.commit(&mut au).is_ok());
            }
            // Make sure there are no errors.
            assert!(qs.verify(&mut au_test).len() == 0);

            au.append_scope(au_test);
        });
        // Dump the raw audit log.
        println!("{}", au);
    }};
}

/*
#[macro_export]
macro_rules! run_post_create_test {
}

#[macro_export]
macro_rules! run_post_modify_test {
}

#[macro_export]
macro_rules! run_post_delete_test {
}
*/
