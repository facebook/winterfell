// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::num;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_utils::rand_vector;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};
use std::time::Duration;

use math::{
    fft::{self, fft_inputs::FftInputs},
    fields::f64::BaseElement,
    FieldElement, StarkField,
};

use winter_prover::{
    evaluate_poly_with_offset, evaluate_poly_with_offset_concurrent, Matrix, RowMatrix, ARR_SIZE,
};

const SIZE: usize = 524_288;
const NUM_POLYS: [usize; 4] = [16, 32, 72, 96];

fn interpolate_columns(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_interpolate_columns");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &num_poly in NUM_POLYS.iter() {
        let mut columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(column_matrix.columns).for_each(|column| {
                    fft::serial::interpolate_poly(column.as_mut_slice(), &inv_twiddles)
                });
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(column_matrix.columns).for_each(|column| {
                    fft::serial::interpolate_poly_with_offset(
                        column.as_mut_slice(),
                        &inv_twiddles,
                        BaseElement::GENERATOR,
                    )
                });
            });
        });
    }
    group.finish();
}

fn evaluate_columns(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_evaluate_columns");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let blowup_factor = 8;

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(column_matrix.columns).for_each(|column| {
                    fft::serial::evaluate_poly(column.as_mut_slice(), &twiddles);
                });
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
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

fn interpolate_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("matrix_interpolate_matrix");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &num_poly in NUM_POLYS.iter() {
        let num_segments = num_poly / ARR_SIZE;
        let mut matrix_vec: Vec<RowMatrix<BaseElement>> = Vec::new();
        for _ in 0..num_segments {
            // create a vector of arrays of size ARR_SIZE.
            let segment: Vec<[BaseElement; ARR_SIZE]> =
                (0..SIZE).map(|_| to_array(rand_vector(ARR_SIZE))).collect();
            matrix_vec.push(RowMatrix::new(segment, num_poly));
        }

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(matrix_vec)
                    .for_each(|matrix| RowMatrix::interpolate_poly(matrix, &inv_twiddles))
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let num_segments = num_poly / ARR_SIZE;
        let mut matrix_vec: Vec<RowMatrix<BaseElement>> = Vec::new();
        for _ in 0..num_segments {
            let segment: Vec<[BaseElement; ARR_SIZE]> =
                (0..SIZE).map(|_| to_array(rand_vector(ARR_SIZE))).collect();
            matrix_vec.push(RowMatrix::new(segment, num_poly));
        }

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(matrix_vec).for_each(|matrix| {
                    RowMatrix::interpolate_poly_with_offset(
                        matrix,
                        &inv_twiddles,
                        BaseElement::GENERATOR,
                    )
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
        let num_segments = num_poly / ARR_SIZE;
        let mut matrix_vec: Vec<RowMatrix<BaseElement>> = Vec::new();
        for _ in 0..num_segments {
            let segment: Vec<[BaseElement; ARR_SIZE]> =
                (0..SIZE).map(|_| to_array(rand_vector(ARR_SIZE))).collect();
            matrix_vec.push(RowMatrix::new(segment, num_poly));
        }

        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(matrix_vec).for_each(|matrix| {
                    RowMatrix::evaluate_poly(matrix, &twiddles);
                });
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let num_segments = num_poly / ARR_SIZE;
        let mut matrix_vec: Vec<RowMatrix<BaseElement>> = Vec::new();
        for _ in 0..num_segments {
            let segment: Vec<[BaseElement; ARR_SIZE]> =
                (0..SIZE).map(|_| to_array(rand_vector(ARR_SIZE))).collect();
            matrix_vec.push(RowMatrix::new(segment, num_poly));
        }

        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(matrix_vec).for_each(|matrix| {
                    evaluate_poly_with_offset(
                        matrix,
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

criterion_group!(
    matrix_group,
    interpolate_matrix,
    evaluate_matrix,
    interpolate_columns,
    evaluate_columns,
);
criterion_main!(matrix_group);

#[macro_export]
macro_rules! iter_mut {
    ($e: expr) => {{
        // #[cfg(feature = "concurrent")]
        // let result = $e.par_iter_mut();

        // #[cfg(not(feature = "concurrent"))]
        let result = $e.iter_mut();

        result
    }};
    ($e: expr, $min_len: expr) => {{
        // #[cfg(feature = "concurrent")]
        // let result = $e.par_iter().with_min_len($min_len);

        // #[cfg(not(feature = "concurrent"))]
        // let result = $e.iter();

        // result
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
