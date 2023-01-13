// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_utils::rand_vector;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};
use std::time::Duration;

use math::{
    fft::{self},
    fields::f64::BaseElement,
    StarkField,
};

use winter_prover::{
    evaluate_poly_with_offset, evaluate_poly_with_offset_concurrent, Matrix, RowMatrix,
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
                    fft::concurrent::interpolate_poly(column.as_mut_slice(), &inv_twiddles)
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
                    fft::concurrent::interpolate_poly_with_offset(
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
        let mut columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(column_matrix.columns).for_each(|column| {
                    fft::concurrent::evaluate_poly(column.as_mut_slice(), &twiddles);
                });
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let mut columns: Vec<Vec<BaseElement>> = (0..num_poly).map(|_| rand_vector(SIZE)).collect();
        let mut column_matrix = Matrix::new(columns);
        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                iter_mut!(column_matrix.columns).for_each(|column| {
                    fft::concurrent::evaluate_poly_with_offset(
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
        let rows: Vec<Vec<BaseElement>> = (0..SIZE).map(|_| rand_vector(num_poly)).collect();

        let row_width = rows[0].len();
        let mut flatten_table = rows.into_iter().flatten().collect::<Vec<_>>();
        let mut table = RowMatrix::new(&mut flatten_table, row_width);

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                RowMatrix::interpolate_poly_concurrent(&mut table, &inv_twiddles)
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let rows: Vec<Vec<BaseElement>> = (0..SIZE).map(|_| rand_vector(num_poly)).collect();

        let row_width = rows[0].len();
        let mut flatten_table = rows.into_iter().flatten().collect::<Vec<_>>();
        let mut table = RowMatrix::new(&mut flatten_table, row_width);

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                RowMatrix::interpolate_poly_with_offset_concurrent(
                    &mut table,
                    &inv_twiddles,
                    BaseElement::GENERATOR,
                )
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
        let rows: Vec<Vec<BaseElement>> = (0..SIZE).map(|_| rand_vector(num_poly)).collect();

        let row_width = rows[0].len();
        let mut flatten_table = rows.into_iter().flatten().collect::<Vec<_>>();
        let mut table = RowMatrix::new(&mut flatten_table, row_width);

        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("simple", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                RowMatrix::evaluate_poly_concurrent(&mut table, &twiddles)
            });
        });
    }

    for &num_poly in NUM_POLYS.iter() {
        let rows: Vec<Vec<BaseElement>> = (0..SIZE).map(|_| rand_vector(num_poly)).collect();

        let row_width = rows[0].len();
        let mut flatten_table = rows.into_iter().flatten().collect::<Vec<_>>();
        let table = RowMatrix::new(&mut flatten_table, row_width);

        let twiddles = fft::get_twiddles::<BaseElement>(SIZE);
        group.bench_function(BenchmarkId::new("with_offset", num_poly), |bench| {
            bench.iter_with_large_drop(|| {
                evaluate_poly_with_offset_concurrent(
                    &table,
                    &twiddles,
                    BaseElement::GENERATOR,
                    blowup_factor,
                )
            });
        });
    }
    group.finish();
}

criterion_group!(
    matrix_group,
    interpolate_columns,
    interpolate_matrix,
    evaluate_columns,
    evaluate_matrix
);
criterion_main!(matrix_group);

#[macro_export]
macro_rules! iter_mut {
    ($e: expr) => {{
        // #[cfg(feature = "concurrent")]
        let result = $e.par_iter_mut();

        // #[cfg(not(feature = "concurrent"))]
        // let result = $e.iter();

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
