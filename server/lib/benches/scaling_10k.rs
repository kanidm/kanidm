use std::time::{Duration, Instant, SystemTime};

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};

use kanidmd_lib::entry::{Entry, EntryInit, EntryNew};
use kanidmd_lib::entry_init;
use kanidmd_lib::prelude::{Attribute, EntryClass};
use kanidmd_lib::testkit::{setup_idm_test, TestConfiguration};
use kanidmd_lib::value::Value;

pub fn duration_from_epoch_now() -> Duration {
    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("invalid duration from epoch now")
}

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
                println!("iters, size -> {iters:?}, {size:?}");

                for _i in 0..iters {
                    let mut rt = tokio::runtime::Builder::new_current_thread();
                    elapsed = rt
                        .enable_all()
                        .build()
                        .expect("Failed building the Runtime")
                        .block_on(async {
                            let (idms, _idms_delayed, _idms_audit) =
                                setup_idm_test(TestConfiguration::default()).await;

                            let ct = duration_from_epoch_now();
                            let start = Instant::now();
                            for counter in 0..size {
                                let mut idms_prox_write = idms.proxy_write(ct).await;
                                let name = format!("testperson_{counter}");
                                let e1 = entry_init!(
                                    (Attribute::Class, EntryClass::Object.to_value()),
                                    (Attribute::Class, EntryClass::Person.to_value()),
                                    (Attribute::Class, EntryClass::Account.to_value()),
                                    (Attribute::Name, Value::new_iname(&name)),
                                    (Attribute::Description, Value::new_utf8s("criterion")),
                                    (Attribute::DisplayName, Value::new_utf8s(&name))
                                );

                                let cr = idms_prox_write.qs_write.internal_create(vec![e1]);
                                assert!(cr.is_ok());

                                idms_prox_write.commit().expect("Must not fail");
                            }
                            elapsed.checked_add(start.elapsed()).unwrap()
                        });
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
                println!("iters, size -> {iters:?}, {size:?}");

                let data: Vec<_> = (0..size)
                    .map(|i| {
                        let name = format!("testperson_{i}");
                        entry_init!(
                            (Attribute::Class, EntryClass::Object.to_value()),
                            (Attribute::Class, EntryClass::Person.to_value()),
                            (Attribute::Class, EntryClass::Account.to_value()),
                            (Attribute::Name, Value::new_iname(&name)),
                            (Attribute::Description, Value::new_utf8s("criterion")),
                            (Attribute::DisplayName, Value::new_utf8s(&name))
                        )
                    })
                    .collect();

                for _i in 0..iters {
                    let mut rt = tokio::runtime::Builder::new_current_thread();
                    elapsed = rt
                        .enable_all()
                        .build()
                        .expect("Failed building the Runtime")
                        .block_on(async {
                            let (idms, _idms_delayed, _idms_audit) =
                                setup_idm_test(TestConfiguration::default()).await;

                            let ct = duration_from_epoch_now();
                            let start = Instant::now();

                            let mut idms_prox_write = idms.proxy_write(ct).await;
                            let cr = idms_prox_write.qs_write.internal_create(data.clone());
                            assert!(cr.is_ok());

                            idms_prox_write.commit().expect("Must not fail");
                            elapsed.checked_add(start.elapsed()).unwrap()
                        });
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
