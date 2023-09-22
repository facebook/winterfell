// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use examples::{fibonacci, Example};
use std::time::Duration;
use winter_fri::fri_schedule::FoldingSchedule;
use winterfell::{
    crypto::hashers::Blake3_256, math::fields::f128::BaseElement, FieldExtension, ProofOptions,
};

const SIZES: [usize; 3] = [16_384, 65_536, 262_144];

fn fibonacci(c: &mut Criterion) {
    let mut group = c.benchmark_group("fibonacci");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));

    let fri_constant_schedule = FoldingSchedule::new_constant(4, 255);

    let options = ProofOptions::new(32, 8, 0, FieldExtension::None, &fri_constant_schedule);

    for &size in SIZES.iter() {
        let fib =
            fibonacci::fib2::FibExample::<Blake3_256<BaseElement>>::new(size, options.clone());
        group.bench_function(BenchmarkId::from_parameter(size), |bench| {
            bench.iter(|| fib.prove());
        });
    }
    group.finish();
}

criterion_group!(fibonacci_group, fibonacci);
criterion_main!(fibonacci_group);
