use criterion::{criterion_group, criterion_main, Criterion};

use kanidm;
use kanidm::utils::duration_from_epoch_now;
use kanidm::entry::{Entry, EntryNew, EntryInit, Set};
use kanidm::value::Value;
use kanidm::event::CreateEvent;
use kanidm::server::QueryServer;
use kanidm::idm::server::{IdmServer, IdmServerDelayed};
use kanidm::audit::AuditScope;

use std::time::Duration;
use async_std::task;

pub fn scaling_unloaded_user_create(c: &mut Criterion) {
    kanidm::macros::run_idm_test_no_logging(|_qs: &QueryServer,
                   idms: &IdmServer,
                   _idms_delayed: &IdmServerDelayed,
                   au: &mut AuditScope| {

        let mut counter: usize = 0;

        c.bench_function(
            "unloaded_user_create",
            |b| b.iter(|| {
                let ct = duration_from_epoch_now();

                let idms_prox_write =
                    task::block_on(idms.proxy_write_async(ct));

                let name = format!("testperson_{}", counter);
                let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
                let mut classes = Set::new();
                classes.insert(Value::new_class("object"));
                classes.insert(Value::new_class("person"));
                classes.insert(Value::new_class("account"));
                e1.set_ava("class", classes);
                e1.add_ava("name", Value::new_iname(&name));
                e1.add_ava("description", Value::new_utf8s(&name));
                e1.add_ava("displayname", Value::new_utf8s(&name));

                let ce = CreateEvent::new_internal(vec![e1]);

                let cr = idms_prox_write.qs_write.create(au, &ce);
                assert!(cr.is_ok());

                idms_prox_write.commit(au).expect("Must not fail");
                counter += 1;
            })
        );
    });
}

criterion_group!(
    name = scaling_basic;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .with_plots();
    targets = scaling_unloaded_user_create
);
criterion_main!(scaling_basic);









