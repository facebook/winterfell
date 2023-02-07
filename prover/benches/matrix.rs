// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_utils::rand_vector;
use rayon::prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::time::Duration;

use math::{
    fft::{self, fft_inputs::FftInputs},
    fields::f64::BaseElement,
    FieldElement, StarkField,
};

use winter_prover::{
    evaluate_poly_with_offset, evaluate_poly_with_offset_concurrent, Matrix, RowMatrix, Segment,
    ARR_SIZE,
};

const SIZE: usize = 524_288;
const NUM_POLYS: [usize; 1] = [64];

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
                    fft::serial::evaluate_poly_with_offset(
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
                Segment::from_polys(&column_matrix, blowup_factor);
            });
        });
    }
    group.finish();
}

criterion_group!(matrix_group, evaluate_matrix, evaluate_columns,);
criterion_main!(matrix_group);

#[macro_export]
macro_rules! iter_mut {
    ($e: expr) => {{
        // #[cfg(feature = "concurrent")]
        let result = $e.par_iter_mut();

        // #[cfg(not(feature = "concurrent"))]
        // let result = $e.iter_mut();

        result
    }};
}

#[macro_export]
macro_rules! iter {
    ($e: expr) => {{
        // #[cfg(feature = "concurrent")]
        let result = $e.par_iter();

        // #[cfg(not(feature = "concurrent"))]
        // let result = $e.iter_mut();

        result
    }};
}

/// Convert a vector of field elements to a arrays of field elements. The size of the array is
/// determined by the `ARR_SIZE` constant.
fn to_array<E: FieldElement>(v: Vec<E>) -> [E; ARR_SIZE] {
    debug_assert_eq!(v.len(), ARR_SIZE);
    let mut result = [E::ZERO; ARR_SIZE];
    for (i, e) in v.into_iter().enumerate() {
        result[i] = e;
    }
    result
}
