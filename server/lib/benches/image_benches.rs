/// This file contains benchmarks for the image module so we can work out the best order to run things in
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kanidmd_lib::valueset::image::jpg;
use kanidmd_lib::valueset::image::png;

pub fn bench_png_lodepng_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("png_lodepng_validate");
    group.bench_function("png_lodepng_validate_oversize", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.png",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(filename).unwrap());
        b.iter(|| {
            png::png_lodepng_validate(&contents, black_box(&"oversize_dimensions.png".to_string()))
        })
    });
    group.bench_function("png_lodepng_validate_ok", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.png",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(filename).unwrap());
        b.iter(|| {
            png::png_lodepng_validate(&contents, black_box(&"oversize_dimensions.png".to_string()))
        })
    });
    group.finish();
}

pub fn bench_png_has_trailer(c: &mut Criterion) {
    let mut group = c.benchmark_group("png_has_trailer");
    group.bench_function("png_has_trailer_oversize", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.png",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(filename).unwrap());
        b.iter(|| png::png_has_trailer(&contents));
    });
    group.bench_function("png_has_trailer_ok", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/ok.png",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(filename).unwrap());
        b.iter(|| png::png_has_trailer(&contents));
    });
    group.finish();
}

pub fn bench_jpg(c: &mut Criterion) {
    let mut group = c.benchmark_group("jpg");
    group.bench_function("check_jpg_header", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(filename).unwrap());
        b.iter(|| jpg::check_jpg_header(&contents));
    });
    group.bench_function("has_trailer", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(filename).unwrap());
        b.iter(|| jpg::has_trailer(&contents));
    });
    group.bench_function("use_decoder", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(&filename).unwrap());
        b.iter(|| jpg::validate_decoding(&filename, &contents, image::io::Limits::default()));
    });
    group.finish();
}

pub fn compare_jpg(c: &mut Criterion) {
    let mut group = c.benchmark_group("compare_jpg");
    group.bench_function("header, trailer, decoder", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(&filename).unwrap());
        b.iter(|| {
            assert!(jpg::check_jpg_header(&contents).is_ok());
            assert!(jpg::has_trailer(&contents).is_ok());
            assert!(
                jpg::validate_decoding(&filename, &contents, image::io::Limits::default()).is_ok()
            );
        });
    });
    group.bench_function("trailer, header, decoder", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(&filename).unwrap());
        b.iter(|| {
            assert!(jpg::has_trailer(&contents).is_ok());
            assert!(jpg::check_jpg_header(&contents).is_ok());
            assert!(
                jpg::validate_decoding(&filename, &contents, image::io::Limits::default()).is_ok()
            );
        });
    });
    group.bench_function("decoder, trailer, header", |b| {
        let filename = black_box(format!(
            "{}/src/valueset/image/test_images/oversize_dimensions.jpg",
            env!("CARGO_MANIFEST_DIR")
        ));
        let contents = black_box(std::fs::read(&filename).unwrap());
        b.iter(|| {
            assert!(
                jpg::validate_decoding(&filename, &contents, image::io::Limits::default()).is_ok()
            );
            assert!(jpg::has_trailer(&contents).is_ok());
            assert!(jpg::check_jpg_header(&contents).is_ok());
        });
    });

    group.finish();
}

criterion_group!(
    name = png_tests;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(15))
        .with_plots();
    targets = bench_png_lodepng_validate, bench_png_has_trailer, bench_jpg, compare_jpg
);
criterion_main!(png_tests);
