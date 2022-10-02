use std::time::{Duration, Instant};

use async_std::task;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use kanidm;
use kanidm::entry::{Entry, EntryInit, EntryNew};
use kanidm::entry_init;
use kanidm::idm::server::{IdmServer, IdmServerDelayed};
use kanidm::macros::run_idm_test_no_logging;
use kanidm::server::QueryServer;
use kanidm::utils::duration_from_epoch_now;
use kanidm::value::Value;

pub fn scaling_user_create_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("user_create_single");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(5));
    group.measurement_time(Duration::from_secs(120));

    for size in &[100, 250, 500, 1000, 1500, 2000, 5000, 10000] {
        group.throughput(Throughput::Elements(*size));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|iters| {
                let mut elapsed = Duration::from_secs(0);
                println!("iters, size -> {:?}, {:?}", iters, size);

                for _i in 0..iters {
                    run_idm_test_no_logging(
                        |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
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

                                let cr = idms_prox_write.qs_write.internal_create(vec![e1]);
                                assert!(cr.is_ok());

                                idms_prox_write.commit().expect("Must not fail");
                            }
                            elapsed = elapsed.checked_add(start.elapsed()).unwrap();
                        },
                    );
                }
                elapsed
            });
        });
    }
    group.finish();
}

pub fn scaling_user_create_batched(c: &mut Criterion) {
    let mut group = c.benchmark_group("user_create_batched");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_secs(5));
    group.measurement_time(Duration::from_secs(120));

    for size in &[100, 250, 500, 1000, 1500, 2000, 5000, 10000] {
        group.throughput(Throughput::Elements(*size));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_custom(|iters| {
                let mut elapsed = Duration::from_secs(0);
                println!("iters, size -> {:?}, {:?}", iters, size);

                let data: Vec<_> = (0..size)
                    .into_iter()
                    .map(|i| {
                        let name = format!("testperson_{}", i);
                        entry_init!(
                            ("class", Value::new_class("object")),
                            ("class", Value::new_class("person")),
                            ("class", Value::new_class("account")),
                            ("name", Value::new_iname(&name)),
                            ("description", Value::new_utf8s("criterion")),
                            ("displayname", Value::new_utf8s(&name))
                        )
                    })
                    .collect();

                for _i in 0..iters {
                    kanidm::macros::run_idm_test_no_logging(
                        |_qs: &QueryServer, idms: &IdmServer, _idms_delayed: &IdmServerDelayed| {
                            let ct = duration_from_epoch_now();

                            let start = Instant::now();

                            let idms_prox_write = task::block_on(idms.proxy_write_async(ct));
                            let cr = idms_prox_write.qs_write.internal_create(data.clone());
                            assert!(cr.is_ok());

                            idms_prox_write.commit().expect("Must not fail");
                            elapsed = elapsed.checked_add(start.elapsed()).unwrap();
                        },
                    );
                }
                elapsed
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = scaling_basic;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(15))
        .with_plots();
    targets = scaling_user_create_single, scaling_user_create_batched
);
criterion_main!(scaling_basic);
