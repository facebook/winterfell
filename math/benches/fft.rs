// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand_utils::rand_vector;
use std::time::Duration;
use winter_math::{
    fft,
    fields::{f128, f62, f64, CubeExtension, QuadExtension},
    FieldElement, StarkField,
};

const SIZES: [usize; 3] = [262_144, 524_288, 1_048_576];

fn fft_evaluate_poly<B, E>(c: &mut Criterion, field_name: &str)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    let mut group = c.benchmark_group(format!("{}/fft_evaluate_poly", field_name));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let blowup_factor = 8;

    for &size in SIZES.iter() {
        let p: Vec<E> = rand_vector(size / blowup_factor);
        let twiddles: Vec<B> = fft::get_twiddles(size);
        group.bench_function(BenchmarkId::new("simple", size), |bench| {
            bench.iter_with_large_drop(|| {
                let mut result = vec![E::ZERO; size];
                result[..p.len()].copy_from_slice(&p);
                fft::evaluate_poly(&mut result, &twiddles);
                result
            });
        });
    }

    for &size in SIZES.iter() {
        let p: Vec<E> = rand_vector(size / blowup_factor);
        let twiddles: Vec<B> = fft::get_twiddles(size / blowup_factor);
        group.bench_function(BenchmarkId::new("with_offset", size), |bench| {
            bench.iter_with_large_drop(|| {
                let result =
                    fft::evaluate_poly_with_offset(&p, &twiddles, B::GENERATOR, blowup_factor);
                result
            });
        });
    }

    group.finish();
}

fn fft_interpolate_poly<B, E>(c: &mut Criterion, field_name: &str)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    let mut group = c.benchmark_group(format!("{}/fft_interpolate_poly", field_name));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SIZES.iter() {
        let p: Vec<E> = rand_vector(size);
        let inv_twiddles: Vec<B> = fft::get_inv_twiddles(size);
        group.bench_function(BenchmarkId::new("simple", size), |bench| {
            bench.iter_batched_ref(
                || p.clone(),
                |mut p| fft::interpolate_poly(&mut p, &inv_twiddles),
                BatchSize::LargeInput,
            );
        });
    }

    for &size in SIZES.iter() {
        let p: Vec<E> = rand_vector(size);
        let inv_twiddles: Vec<B> = fft::get_inv_twiddles(size);
        group.bench_function(BenchmarkId::new("with_offset", size), |bench| {
            bench.iter_batched_ref(
                || p.clone(),
                |mut p| fft::interpolate_poly_with_offset(&mut p, &inv_twiddles, B::GENERATOR),
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
            bench.iter(|| fft::get_twiddles::<f128::BaseElement>(size));
        });
    }
    group.finish();
}

fn bench_fft(c: &mut Criterion) {
    fft_evaluate_poly::<f62::BaseElement, f62::BaseElement>(c, "f62");
    fft_evaluate_poly::<f64::BaseElement, f64::BaseElement>(c, "f64");
    fft_evaluate_poly::<f128::BaseElement, f128::BaseElement>(c, "f128");

    fft_evaluate_poly::<f62::BaseElement, QuadExtension<f62::BaseElement>>(c, "f62_quad");
    fft_evaluate_poly::<f64::BaseElement, QuadExtension<f64::BaseElement>>(c, "f64_quad");
    fft_evaluate_poly::<f128::BaseElement, QuadExtension<f128::BaseElement>>(c, "f128_quad");

    fft_evaluate_poly::<f64::BaseElement, CubeExtension<f64::BaseElement>>(c, "f64_cube");

    fft_interpolate_poly::<f62::BaseElement, f62::BaseElement>(c, "f62");
    fft_interpolate_poly::<f64::BaseElement, f64::BaseElement>(c, "f64");
    fft_interpolate_poly::<f128::BaseElement, f128::BaseElement>(c, "f128");
}

criterion_group!(fft_group, bench_fft, get_twiddles);
criterion_main!(fft_group);
