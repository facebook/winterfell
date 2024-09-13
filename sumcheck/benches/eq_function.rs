// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use math::fields::f64::BaseElement;
use rand_utils::rand_vector;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use winter_sumcheck::EqFunction;

const LOG_POLY_SIZE: [usize; 2] = [18, 20];

fn evaluate_eq(c: &mut Criterion) {
    let mut group = c.benchmark_group("EQ function evaluations");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &log_poly_size in LOG_POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("", log_poly_size), |b| {
            b.iter_batched(
                || {
                    let randomness: Vec<BaseElement> = rand_vector(log_poly_size);
                    EqFunction::new(randomness.into())
                },
                |eq_function| eq_function.evaluations(),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(group, evaluate_eq);
criterion_main!(group);
