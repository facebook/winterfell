// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use math::{fields::f64::BaseElement, FieldElement};
use rand_utils::rand_vector;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

const LOG_POLY_SIZE: [usize; 2] = [18, 20];

fn evaluate_eq_serial(c: &mut Criterion) {
    let mut group = c.benchmark_group("EQ function evaluations");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &log_poly_size in LOG_POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("serial", log_poly_size), |b| {
            b.iter_batched(
                || {
                    let randomness: Vec<BaseElement> = rand_vector(log_poly_size);
                    randomness
                },
                |rand| eq_evaluations(&rand),
                BatchSize::SmallInput,
            )
        });
    }
}

fn evaluate_eq_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("EQ function evaluations");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &log_poly_size in LOG_POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("parallel", log_poly_size), |b| {
            b.iter_batched(
                || {
                    let randomness: Vec<BaseElement> = rand_vector(log_poly_size);
                    randomness
                },
                |rand| eq_evaluations_par(&rand),
                BatchSize::SmallInput,
            )
        });
    }
}

fn eq_evaluations<E: FieldElement>(query: &[E]) -> Vec<E> {
    let n = 1 << query.len();
    let mut evals = unsafe { utils::uninit_vector(n) };

    let mut size = 1;
    evals[0] = E::ONE;
    for r_i in query.iter() {
        let (left_evals, right_evals) = evals.split_at_mut(size);
        left_evals.iter_mut().zip(right_evals.iter_mut()).for_each(|(left, right)| {
            let factor = *left;
            *right = factor * *r_i;
            *left -= *right;
        });

        size *= 2;
    }
    evals
}

fn eq_evaluations_par<E: FieldElement>(query: &[E]) -> Vec<E> {
    let n = 1 << query.len();
    let mut evals = unsafe { utils::uninit_vector(n) };

    let mut size = 1;
    evals[0] = E::ONE;
    for r_i in query.iter() {
        let (left_evals, right_evals) = evals.split_at_mut(size);
        left_evals
            .par_iter_mut()
            .zip(right_evals.par_iter_mut())
            .for_each(|(left, right)| {
                let factor = *left;
                *right = factor * *r_i;
                *left -= *right;
            });

        size <<= 1;
    }
    evals
}

criterion_group!(group, evaluate_eq_serial, evaluate_eq_parallel);
criterion_main!(group);
