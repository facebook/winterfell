// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use math::{fields::f64::BaseElement, FieldElement};
use rand_utils::{rand_value, rand_vector};
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

const POLY_SIZE: [usize; 2] = [1 << 18, 1 << 20];

fn bind_variable_serial(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bind variable evaluations");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &poly_size in POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("serial", poly_size), |b| {
            b.iter_batched(
                || {
                    let random_challenge: BaseElement = rand_value();
                    let poly_evals: Vec<BaseElement> = rand_vector(poly_size);
                    (random_challenge, poly_evals)
                },
                |(random_challenge, poly_evals)| {
                    let mut poly_evals = poly_evals;
                    bind_least_significant_variable_serial(&mut poly_evals, random_challenge)
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn bind_variable_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bind variable function evaluations");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &poly_size in POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("parallel", poly_size), |b| {
            b.iter_batched(
                || {
                    let random_challenge: BaseElement = rand_value();
                    let poly_evals: Vec<BaseElement> = rand_vector(poly_size);
                    (random_challenge, poly_evals)
                },
                |(random_challenge, poly_evals)| {
                    let mut poly_evals = poly_evals;
                    bind_least_significant_variable_parallel(&mut poly_evals, random_challenge)
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn bind_least_significant_variable_serial<E: FieldElement>(
    evaluations: &mut Vec<E>,
    round_challenge: E,
) {
    let num_evals = evaluations.len() >> 1;

    for i in 0..num_evals {
        evaluations[i] = evaluations[i << 1]
            + round_challenge * (evaluations[(i << 1) + 1] - evaluations[i << 1]);
    }
    evaluations.truncate(num_evals);
}

fn bind_least_significant_variable_parallel<E: FieldElement>(
    evaluations: &mut Vec<E>,
    round_challenge: E,
) {
    let num_evals = evaluations.len() >> 1;

    let mut result = unsafe { utils::uninit_vector(num_evals) };
    result.par_iter_mut().enumerate().for_each(|(i, ev)| {
        *ev = evaluations[i << 1]
            + round_challenge * (evaluations[(i << 1) + 1] - evaluations[i << 1])
    });
    *evaluations = result
}

criterion_group!(group, bind_variable_serial, bind_variable_parallel);
criterion_main!(group);
