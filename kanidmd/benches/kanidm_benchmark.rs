use criterion::{criterion_group, criterion_main, Criterion};

#[macro_use]
use kanidm;
use kanidm::constants::UUID_ADMIN;

pub fn criterion_benchmark_search_1(c: &mut Criterion) {
    // Setup
    //
    run_test!(|server: &QueryServer, audit: &mut AuditScope| {
        let filt = filter!(f_eq("name", PartialValue::new_iutf8s("testperson")));
        let admin = server_txn
            .internal_search_uuid(audit, &UUID_ADMIN)
            .expect("failed");

        let se1 = unsafe { SearchEvent::new_impersonate_entry(admin.clone(), filt.clone()) };

        c.bench_function("search 2000", |b| {
            b.iter(|| {
                let r1 = server_txn.search(audit, &se1).expect("search failure");
                assert!(r1.is_empty());
            })
        });
    })
}

criterion_group!(benches, criterion_benchmark_search_1);
criterion_main!(benches);
