// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand_utils::rand_vector;
use std::time::Duration;
use winter_math::{
    fft,
    fields::{f128::BaseElement, QuadExtension},
    FieldElement, StarkField,
};

const SIZES: [usize; 3] = [262_144, 524_288, 1_048_576];

fn fft_evaluate_poly(c: &mut Criterion) {
    let mut group = c.benchmark_group("fft_evaluate_poly");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let blowup_factor = 8;

    for &size in SIZES.iter() {
        let p: Vec<BaseElement> = rand_vector(size / blowup_factor);
        let twiddles: Vec<BaseElement> = fft::get_twiddles(size);
        group.bench_function(BenchmarkId::new("simple", size), |bench| {
            bench.iter_with_large_drop(|| {
                let mut result = vec![BaseElement::ZERO; size];
                result[..p.len()].copy_from_slice(&p);
                fft::evaluate_poly(&mut result, &twiddles);
                result
            });
        });
    }

    for &size in SIZES.iter() {
        let p: Vec<BaseElement> = rand_vector(size / blowup_factor);
        let twiddles: Vec<BaseElement> = fft::get_twiddles(size / blowup_factor);
        group.bench_function(BenchmarkId::new("with_offset", size), |bench| {
            bench.iter_with_large_drop(|| {
                let result = fft::evaluate_poly_with_offset(
                    &p,
                    &twiddles,
                    BaseElement::GENERATOR,
                    blowup_factor,
                );
                result
            });
        });
    }

    for &size in SIZES.iter() {
        let twiddles: Vec<BaseElement> = fft::get_twiddles(size);
        let p: Vec<QuadExtension<BaseElement>> = rand_vector(size / blowup_factor);
        group.bench_function(BenchmarkId::new("extension", size), |bench| {
            bench.iter_with_large_drop(|| {
                let mut result = QuadExtension::<BaseElement>::zeroed_vector(size);
                result[..p.len()].copy_from_slice(&p);
                fft::evaluate_poly(&mut result, &twiddles);
                result
            });
        });
    }

    group.finish();
}

fn fft_interpolate_poly(c: &mut Criterion) {
    let mut group = c.benchmark_group("fft_interpolate_poly");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SIZES.iter() {
        let p: Vec<BaseElement> = rand_vector(size);
        let inv_twiddles: Vec<BaseElement> = fft::get_inv_twiddles(size);
        group.bench_function(BenchmarkId::new("simple", size), |bench| {
            bench.iter_batched_ref(
                || p.clone(),
                |mut p| fft::interpolate_poly(&mut p, &inv_twiddles),
                BatchSize::LargeInput,
            );
        });
    }

    for &size in SIZES.iter() {
        let p: Vec<BaseElement> = rand_vector(size);
        let inv_twiddles: Vec<BaseElement> = fft::get_inv_twiddles(size);
        group.bench_function(BenchmarkId::new("with_offset", size), |bench| {
            bench.iter_batched_ref(
                || p.clone(),
                |mut p| {
                    fft::interpolate_poly_with_offset(&mut p, &inv_twiddles, BaseElement::GENERATOR)
                },
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn get_twiddles(c: &mut Criterion) {
    let mut group = c.benchmark_group("fft_get_twiddles");
    group.sample_size(10);
    for &size in SIZES.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |bench, &size| {
            bench.iter(|| fft::get_twiddles::<BaseElement>(size));
        });
    }
    group.finish();
}

criterion_group!(
    fft_group,
    fft_evaluate_poly,
    fft_interpolate_poly,
    get_twiddles
);
criterion_main!(fft_group);
