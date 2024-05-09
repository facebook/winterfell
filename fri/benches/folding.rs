// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use math::{fields::f128::BaseElement, get_power_series, polynom, StarkField};
use rand_utils::{rand_value, rand_vector};
use utils::group_slice_elements;
use winter_fri::folding;

static BATCH_SIZES: [usize; 3] = [65536, 131072, 262144];

pub fn interpolate_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("interpolate batch");

    for &size in &BATCH_SIZES {
        let (xs, ys) = build_coordinate_batches(size);
        group.bench_function(BenchmarkId::new("generic", size), |b| {
            b.iter(|| polynom::interpolate_batch(&xs, &ys))
        });
    }
}

pub fn apply_drp(c: &mut Criterion) {
    let mut group = c.benchmark_group("drp");

    for &size in &BATCH_SIZES {
        let (_, ys) = build_coordinate_batches(size);
        let alpha: BaseElement = rand_value();
        group.bench_function(BenchmarkId::new("base field", size), |b| {
            b.iter(|| folding::apply_drp(&ys, BaseElement::GENERATOR, alpha))
        });
    }
}

criterion_group!(quartic_group, interpolate_batch, apply_drp);
criterion_main!(quartic_group);

// HELPER FUNCTIONS
// ================================================================================================

fn build_coordinate_batches(batch_size: usize) -> (Vec<[BaseElement; 4]>, Vec<[BaseElement; 4]>) {
    let r = BaseElement::get_root_of_unity(batch_size.ilog2());
    let xs = group_slice_elements(&get_power_series(r, batch_size)).to_vec();
    let ys = group_slice_elements(&rand_vector::<BaseElement>(batch_size)).to_vec();
    (xs, ys)
}
