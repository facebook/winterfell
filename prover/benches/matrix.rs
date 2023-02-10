// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use math::{fft, fields::f64::BaseElement, StarkField};
use rand_utils::rand_vector;

#[cfg(feature = "concurrent")]
use utils::rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};

use std::time::Duration;
use utils::iter_mut;
use winter_prover::{Matrix, Segments};
const SIZE: usize = 524288;
const NUM_POLYS: [usize; 4] = [16, 32, 64, 96];

fn evaluate_columns(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_columns");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let blowup_factor = 8;

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
                iter_mut!(column_matrix.columns).for_each(|column| {
                    fft::evaluate_poly_with_offset(
                        column.as_mut_slice(),
                        &twiddles,
                        BaseElement::GENERATOR,
                        blowup_factor,
                    );
                });
            });
        });
    }
    group.finish();
}

fn evaluate_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_matrix");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let blowup_factor = 8;

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let column_matrix = Matrix::new(columns);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                let segments = Segments::from_polys(&column_matrix, blowup_factor);
                segments.transpose_to_gpu_friendly_matrix();
            });
        });
    }
    group.finish();
}

criterion_group!(matrix_group, evaluate_matrix, evaluate_columns,);
criterion_main!(matrix_group);
