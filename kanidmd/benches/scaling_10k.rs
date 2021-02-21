use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

use kanidm;
use kanidm::audit::AuditScope;
use kanidm::entry::{Entry, EntryInit, EntryNew};
use kanidm::entry_init;
use kanidm::filter::{f_eq, Filter};
use kanidm::idm::server::{IdmServer, IdmServerDelayed};
use kanidm::server::QueryServer;
use kanidm::utils::duration_from_epoch_now;
use kanidm::value::{PartialValue, Value};

use async_std::task;
use std::time::{Duration, Instant};

pub fn scaling_unloaded_user_create(c: &mut Criterion) {
    kanidm::macros::run_idm_test_no_logging(
        |_qs: &QueryServer,
         idms: &IdmServer,
         _idms_delayed: &IdmServerDelayed,
         au: &mut AuditScope| {
            let mut group = c.benchmark_group("unloaded_user_create");
            group.sample_size(10);
            group.sampling_mode(SamplingMode::Flat);

            for size in &[100, 250, 500, 1000] {
                group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
                    b.iter_custom(|iters| {
                        println!("iters, size -> {:?}, {:?}", iters, size);
                        let ct = duration_from_epoch_now();

                        let start = Instant::now();
                        for counter in 0..size {
                            let idms_prox_write = task::block_on(idms.proxy_write_async(ct));

                            let name = format!("testperson_{}", counter);
                            let e1 = entry_init!(
                                ("class", Value::new_class("object")),
                                ("class", Value::new_class("person")),
                                ("class", Value::new_class("account")),
                                ("name", Value::new_iname(&name)),
                                ("description", Value::new_utf8s("criterion")),
                                ("displayname", Value::new_utf8s(&name))
                            );

                            let cr = idms_prox_write.qs_write.internal_create(au, vec![e1]);
                            assert!(cr.is_ok());

                            idms_prox_write.commit(au).expect("Must not fail");
                        }
                        let elapsed = start.elapsed();

                        // Clean up.
                        let idms_prox_write = task::block_on(idms.proxy_write_async(ct));
                        assert!(idms_prox_write
                            .qs_write
                            .internal_delete(
                                au,
                                &Filter::new_ignore_hidden(f_eq(
                                    "description",
                                    PartialValue::new_utf8s("criterion")
                                ))
                            )
                            .is_ok());
                        idms_prox_write.commit(au).expect("Must not fail");

                        // Return the result.
                        elapsed
                    });
                });
            }
            group.finish();
        },
    );
}

criterion_group!(
    name = scaling_basic;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(15))
        .with_plots();
    targets = scaling_unloaded_user_create
);
criterion_main!(scaling_basic);
