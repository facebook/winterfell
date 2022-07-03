// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use rand_utils::rand_vector;
use std::time::Duration;
use utils::iter_mut;
use winter_math::{
    fft,
    fields::{f62, f64, f64::BaseElement, CubeExtension, QuadExtension},
    FieldElement, RowMajorTable, StarkField,
};

const SIZES: [usize; 3] = [262_144, 524_288, 1_048_576];

fn interpolate_columns(c: &mut Criterion) {
    let mut group = c.benchmark_group("interpolate_columns");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SIZES.iter() {
        let num_cols = 128;
        let stride = 8;
        let mut columns: Vec<Vec<BaseElement>> = (0..num_cols).map(|_| rand_vector(size)).collect();
        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(size);
        group.bench_function(BenchmarkId::new("columns", size), |bench| {
            bench.iter_with_large_drop(|| {
                for column in columns.iter_mut() {
                    fft::interpolate_poly(column, &inv_twiddles);
                }
            });
        });
    }
    group.finish();
}

fn interpolate_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("interpolate_matrix");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &size in SIZES.iter() {
        let num_cols = 128;
        let stride = 8;
        let mut rows: Vec<Vec<BaseElement>> = (0..size).map(|_| rand_vector(num_cols)).collect();
        let mut table = RowMajorTable::from_rows(rows);
        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(size);
        group.bench_function(BenchmarkId::new("matrix", size), |bench| {
            bench.iter_with_large_drop(|| {
                fft::matrix::interpolate_poly(&mut table, &inv_twiddles);
            });
        });
    }
    group.finish();
}

criterion_group!(matrix_group, interpolate_columns, interpolate_matrix);
criterion_main!(matrix_group);
