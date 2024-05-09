// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use math::{fft, fields::f64::BaseElement, StarkField};
use rand_utils::rand_vector;
use winter_prover::{
    matrix::{ColMatrix, RowMatrix},
    StarkDomain,
};

// CONSTANTS
// ================================================================================================

const SIZE: usize = 524_288;
const BLOWUP_FACTOR: [usize; 3] = [2, 4, 8];
const NUM_POLYS: [usize; 3] = [32, 64, 96];

fn evaluate_columns(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_columns");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let column_matrix = ColMatrix::new(columns);
        for &blowup_factor in BLOWUP_FACTOR.iter() {
            let params = BenchmarkParams { num_poly, blowup_factor };
            group.bench_function(BenchmarkId::new(SIZE.to_string(), params), |bench| {
                bench.iter_with_large_drop(|| {
                    let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
                    let stark_domain =
                        StarkDomain::from_twiddles(twiddles, blowup_factor, BaseElement::GENERATOR);
                    column_matrix.evaluate_columns_over(&stark_domain)
                });
            });
        }
    }
    group.finish();
}

fn evaluate_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_matrix");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let column_matrix = ColMatrix::new(columns);
        for &blowup_factor in BLOWUP_FACTOR.iter() {
            let params = BenchmarkParams { num_poly, blowup_factor };
            group.bench_function(BenchmarkId::new(SIZE.to_string(), params), |bench| {
                bench.iter_with_large_drop(|| {
                    RowMatrix::evaluate_polys::<8>(&column_matrix, blowup_factor);
                });
            });
        }
    }
    group.finish();
}

/// Benchmark parameters.
struct BenchmarkParams {
    num_poly: usize,
    blowup_factor: usize,
}

impl std::fmt::Display for BenchmarkParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "num_poly: {}, blowup_factor: {}", self.num_poly, self.blowup_factor)
    }
}

criterion_group!(matrix_group, evaluate_columns, evaluate_matrix);
criterion_main!(matrix_group);
