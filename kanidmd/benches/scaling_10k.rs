use criterion::{criterion_group, criterion_main, Criterion};

use kanidm;
use kanidm::audit::AuditScope;
use kanidm::entry::{Entry, EntryInit, EntryNew};
use kanidm::entry_init;
use kanidm::event::CreateEvent;
use kanidm::idm::server::{IdmServer, IdmServerDelayed};
use kanidm::server::QueryServer;
use kanidm::utils::duration_from_epoch_now;
use kanidm::value::Value;

use async_std::task;
use std::time::Duration;

pub fn scaling_unloaded_user_create(c: &mut Criterion) {
    kanidm::macros::run_idm_test_no_logging(
        |_qs: &QueryServer,
         idms: &IdmServer,
         _idms_delayed: &IdmServerDelayed,
         au: &mut AuditScope| {
            let mut counter: usize = 0;

            c.bench_function("unloaded_user_create", |b| {
                b.iter(|| {
                    let ct = duration_from_epoch_now();

                    let idms_prox_write = task::block_on(idms.proxy_write_async(ct));

                    let name = format!("testperson_{}", counter);
                    let e1 = entry_init!(
                        ("class", Value::new_class("object")),
                        ("class", Value::new_class("person")),
                        ("class", Value::new_class("account")),
                        ("name", Value::new_iname(&name)),
                        ("description", Value::new_utf8s(&name)),
                        ("displayname", Value::new_utf8s(&name))
                    );

                    let ce = CreateEvent::new_internal(vec![e1]);

                    let cr = idms_prox_write.qs_write.create(au, &ce);
                    assert!(cr.is_ok());

                    idms_prox_write.commit(au).expect("Must not fail");
                    counter += 1;
                })
            });
        },
    );
}

criterion_group!(
    name = scaling_basic;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .with_plots();
    targets = scaling_unloaded_user_create
);
criterion_main!(scaling_basic);
