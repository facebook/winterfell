// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use math::{fft, fields::f64::BaseElement, StarkField};
use rand_utils::rand_vector;
use std::time::Duration;
use winter_prover::{Matrix, RowMatrix, StarkDomain};

// CONSTANTS
// ================================================================================================

const SIZE: usize = 524_288;
const BLOWUP_FACTOR: usize = 8;
const NUM_POLYS: [usize; 4] = [16, 32, 64, 96];

fn evaluate_columns(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_columns");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let column_matrix = Matrix::new(columns);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
                let stark_domain = StarkDomain::from_custom_inputs(
                    twiddles,
                    BLOWUP_FACTOR,
                    BaseElement::GENERATOR,
                );
                column_matrix.evaluate_columns_over(&stark_domain)
            });
        });
    }
    group.finish();
}

fn evaluate_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_matrix");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let column_matrix = Matrix::new(columns);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                RowMatrix::from_polys(&column_matrix, BLOWUP_FACTOR);
            });
        });
    }
    group.finish();
}

criterion_group!(matrix_group, evaluate_matrix, evaluate_columns,);
criterion_main!(matrix_group);
