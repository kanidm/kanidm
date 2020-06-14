#[cfg(test)]
macro_rules! setup_test {
    (
        $au:expr,
        $preload_entries:ident
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
        let be = Backend::new($au, "", 1).expect("Failed to init BE");

        let schema_outer = Schema::new($au).expect("Failed to init schema");
        let qs = QueryServer::new(be, schema_outer);
        qs.initialise_helper($au, duration_from_epoch_now())
            .expect("init failed!");

        if !$preload_entries.is_empty() {
            let mut qs_write = qs.write(duration_from_epoch_now());
            qs_write
                .internal_create($au, $preload_entries)
                .expect("Failed to preload entries");
            assert!(qs_write.commit($au).is_ok());
        }
        qs
    }};
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
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::event::CreateEvent;
        use crate::schema::Schema;
        use crate::server::QueryServer;
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
                let mut qs_write = qs.write(duration_from_epoch_now());
                let r = qs_write.create(&mut au, &ce);
                debug!("test result: {:?}", r);
                assert!(r == $expect);
                $check(&mut au, &mut qs_write);
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
            let ver = qs.verify(&mut au);
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
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::event::ModifyEvent;
        use crate::schema::Schema;
        use crate::server::QueryServer;
        use crate::utils::duration_from_epoch_now;

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
                let mut qs_write = qs.write(duration_from_epoch_now());
                let r = lperf_segment!(
                    &mut au,
                    "plugins::macros::run_modify_test -> main_test",
                    || { qs_write.modify(&mut au, &me) }
                );
                lperf_segment!(
                    &mut au,
                    "plugins::macros::run_modify_test -> post_test check",
                    || { $check(&mut au, &mut qs_write) }
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
            let ver = qs.verify(&mut au);
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
        use crate::audit::AuditScope;
        use crate::be::Backend;
        use crate::event::DeleteEvent;
        use crate::schema::Schema;
        use crate::server::QueryServer;
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
                let mut qs_write = qs.write(duration_from_epoch_now());
                let r = qs_write.delete(&mut au, &de);
                debug!("test result: {:?}", r);
                $check(&mut au, &mut qs_write);
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
            let ver = qs.verify(&mut au);
            debug!("verification -> {:?}", ver);
            assert!(ver.len() == 0);
        });
        // Dump the raw audit log.
        au.write_log();
    }};
}
