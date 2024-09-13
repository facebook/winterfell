// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use math::fields::f64::BaseElement;
use rand_utils::{rand_value, rand_vector};
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use winter_sumcheck::MultiLinearPoly;

const POLY_SIZE: [usize; 2] = [1 << 18, 1 << 20];

fn bind_variable(c: &mut Criterion) {
    let mut group = c.benchmark_group("bind variable ");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &poly_size in POLY_SIZE.iter() {
        group.bench_function(BenchmarkId::new("", poly_size), |b| {
            b.iter_batched(
                || {
                    let random_challenge: BaseElement = rand_value();
                    let poly = MultiLinearPoly::from_evaluations(rand_vector(poly_size));
                    (random_challenge, poly)
                },
                |(random_challenge, mut poly)| {
                    poly.bind_least_significant_variable(random_challenge)
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(group, bind_variable);
criterion_main!(group);
