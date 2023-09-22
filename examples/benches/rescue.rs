// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use examples::{rescue, Example};
use winter_fri::fri_schedule::FoldingSchedule;

use std::time::Duration;
use winterfell::{
    crypto::hashers::Blake3_256, math::fields::f128::BaseElement, FieldExtension, ProofOptions,
};

const SIZES: [usize; 2] = [256, 512];

fn rescue(c: &mut Criterion) {
    let mut group = c.benchmark_group("rescue");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(25));

    let fri_constant_schedule = FoldingSchedule::new_constant(4, 255);

    let options = ProofOptions::new(32, 32, 0, FieldExtension::None, &fri_constant_schedule);

    for &size in SIZES.iter() {
        let resc = rescue::RescueExample::<Blake3_256<BaseElement>>::new(size, options.clone());
        group.bench_function(BenchmarkId::from_parameter(size), |bench| {
            bench.iter(|| resc.prove());
        });
    }
    group.finish();
}

criterion_group!(rescue_group, rescue);
criterion_main!(rescue_group);
