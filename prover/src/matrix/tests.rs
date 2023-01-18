// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    math::{
        fft::{fft_inputs::FftInputs, get_inv_twiddles, get_twiddles},
        fields::f64::BaseElement,
        get_power_series, log2, polynom, StarkField,
    },
    matrix::{evaluate_poly_with_offset, evaluate_poly_with_offset_concurrent, row_matrix},
};

use super::{RowMatrix, ARR_SIZE};
use math::FieldElement;
use rand_utils::rand_vector;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use utils::collections::Vec;

#[test]
fn test_fft_in_place_matrix() {
    // degree 3
    let n = 4;
    let num_polys = 8;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    let mut matrix_vec = build_row_matrix(columns.clone());
    let twiddles = get_twiddles::<BaseElement>(n);
    let domain = build_domain(n);
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &domain);
    }
    let eval_col = transpose(columns);
    let eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();

    for row_matrix in matrix_vec.iter_mut() {
        row_matrix.fft_in_place(&twiddles);
        row_matrix.permute();
    }

    let matrix_data = flatten_row_matrix(matrix_vec);
    assert_eq!(eval_cols_faltten, matrix_data);

    // degree 7
    let n = 8;
    let num_polys = 16;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    let mut matrix_vec = build_row_matrix(columns.clone());
    let twiddles = get_twiddles::<BaseElement>(n);
    let domain = build_domain(n);
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &domain);
    }
    let eval_col = transpose(columns);
    let eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();

    for row_matrix in matrix_vec.iter_mut() {
        row_matrix.fft_in_place(&twiddles);
        row_matrix.permute();
    }

    let matrix_data = flatten_row_matrix(matrix_vec);
    assert_eq!(eval_cols_faltten, matrix_data);

    // degree 15
    let n = 16;
    let num_polys = 64;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    let mut matrix_vec = build_row_matrix(columns.clone());
    let twiddles = get_twiddles::<BaseElement>(n);
    let domain = build_domain(n);
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &domain);
    }
    let eval_col = transpose(columns);
    let eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();

    for row_matrix in matrix_vec.iter_mut() {
        row_matrix.fft_in_place(&twiddles);
        row_matrix.permute();
    }

    let matrix_data = flatten_row_matrix(matrix_vec);
    assert_eq!(eval_cols_faltten, matrix_data);

    // // degree 1023
    let n = 1024;
    let num_polys = 128;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    let mut matrix_vec = build_row_matrix(columns.clone());
    let twiddles = get_twiddles::<BaseElement>(n);
    let domain = build_domain(n);
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &domain);
    }
    let eval_col = transpose(columns);
    let eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();

    for row_matrix in matrix_vec.iter_mut() {
        row_matrix.fft_in_place(&twiddles);
        row_matrix.permute();
    }

    let matrix_data = flatten_row_matrix(matrix_vec);
    assert_eq!(eval_cols_faltten, matrix_data);
}

#[test]
fn test_eval_poly_with_offset_matrix() {
    let n = 128;
    let num_polys = 64;
    let blowup_factor = 8;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    let mut matrix_vec = build_row_matrix(columns.clone());

    let offset = BaseElement::GENERATOR;
    let domain = build_domain(n * blowup_factor);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();

    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &shifted_domain);
    }
    let eval_col = transpose(columns);
    let eval_cols_flatten = eval_col.into_iter().flatten().collect::<Vec<_>>();

    let mut result_vec: Vec<RowMatrix<BaseElement>> = Vec::new();

    let twiddles = get_twiddles::<BaseElement>(n);
    for row_matrix in matrix_vec.iter_mut() {
        let res = evaluate_poly_with_offset(&row_matrix, &twiddles, offset, blowup_factor);
        result_vec.push(RowMatrix::new(res, num_polys));
    }
    let result_data = flatten_row_matrix(result_vec);
    assert_eq!(eval_cols_flatten, result_data);
}

#[test]
fn test_interpolate_poly_with_offset_matrix() {
    // degree 127
    let n = 128;
    let num_polys = 72;

    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
    let matrix_vec = build_row_matrix(columns.clone());
    let matrix_data_flatten = flatten_row_matrix(matrix_vec);

    let offset = BaseElement::GENERATOR;
    let domain = build_domain(n);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &shifted_domain);
    }

    let mut interpolate_matrix_vec = build_row_matrix(columns.clone());
    let inv_twiddles = get_inv_twiddles::<BaseElement>(n);
    for row_matrix in interpolate_matrix_vec.iter_mut() {
        RowMatrix::interpolate_poly_with_offset(row_matrix, &inv_twiddles, offset);
    }
    let result_data = flatten_row_matrix(interpolate_matrix_vec);
    assert_eq!(matrix_data_flatten, result_data);
}

#[test]
fn test_interpolate_poly_matrix() {
    // degree 127
    let n = 128;
    let num_polys = 72;

    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
    let matrix_vec = build_row_matrix(columns.clone());
    let matrix_data_flatten = flatten_row_matrix(matrix_vec);

    let domain = build_domain(n);
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &domain);
    }
    let mut interpolate_matrix_vec = build_row_matrix(columns.clone());
    let inv_twiddles = get_inv_twiddles::<BaseElement>(n);
    for row_matrix in interpolate_matrix_vec.iter_mut() {
        RowMatrix::interpolate_poly(row_matrix, &inv_twiddles);
    }
    let result_data = flatten_row_matrix(interpolate_matrix_vec);
    assert_eq!(matrix_data_flatten, result_data);
}

// // CONCURRENT TESTS
// // ================================================================================================

// #[test]
// fn test_eval_poly_matrix_concurrent() {
//     let n = 1024;
//     let num_polys = 16;
//     let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
//     let rows = transpose_concurrent(columns.clone());
//     let row_width = rows[0].len();
//     let mut flatten_rows = rows.into_iter().flatten().collect::<Vec<_>>();
//     let mut matrix = RowMatrix::new(&mut flatten_rows, row_width);

//     let domain = build_domain(n);
//     for p in columns.iter_mut() {
//         *p = polynom::eval_many(p, &domain);
//     }
//     let eval_col = transpose_concurrent(columns);
//     let eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();

//     let twiddles = get_twiddles::<BaseElement>(n);
//     FftInputs::split_radix_fft(&mut matrix, &twiddles);
//     FftInputs::permute_concurrent(&mut matrix);
//     assert_eq!(eval_cols_faltten, matrix.as_data());
// }

// #[test]
// fn test_eval_poly_with_offset_matrix_concurrent() {
//     let n = 1024;
//     let num_polys = 32;
//     let blowup_factor = 8;
//     let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
//     let rows = transpose_concurrent(columns.clone());
//     let row_width = rows[0].len();
//     let mut flatten_rows = rows.into_iter().flatten().collect::<Vec<_>>();
//     let matrix = RowMatrix::new(&mut flatten_rows, row_width);

//     let offset = BaseElement::GENERATOR;
//     let domain = build_domain(n * blowup_factor);
//     let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();

//     for p in columns.iter_mut() {
//         *p = polynom::eval_many(p, &shifted_domain);
//     }
//     let eval_col = transpose_concurrent(columns);
//     let eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();

//     let twiddles = get_twiddles::<BaseElement>(matrix.len());
//     let eval_vector =
//         evaluate_poly_with_offset_concurrent(&matrix, &twiddles, offset, blowup_factor);
//     assert_eq!(eval_cols_faltten, eval_vector);
// }

// #[test]
// fn test_interpolate_poly_matrix_concurrent() {
//     let n = 1024 * 16;
//     let num_polys = 72;

//     let rows: Vec<Vec<BaseElement>> = (0..n).map(|_| rand_vector(num_polys)).collect();

//     let row_width = rows[0].len();
//     let mut flatten_table = rows.into_iter().flatten().collect::<Vec<_>>();
//     let mut table = RowMatrix::new(&mut flatten_table, row_width);

//     // let twiddles = fft::get_twiddles::<BaseElement>(SIZE);

//     // let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
//     // let rows = transpose_concurrent(columns.clone());
//     // let row_width = rows[0].len();
//     // let mut flatten_rows = rows.into_iter().flatten().collect::<Vec<_>>();
//     // let matrix = RowMatrix::new(&mut flatten_rows, row_width);

//     // let offset = BaseElement::GENERATOR;
//     // let domain = build_domain(n);
//     // for p in columns.iter_mut() {
//     //     *p = polynom::eval_many(p, &domain);
//     // }
//     // let eval_col = transpose_concurrent(columns);
//     // let mut eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();
//     // let mut interpolate_matrix = RowMatrix::new(&mut eval_cols_faltten, row_width);

//     let inv_twiddles = get_inv_twiddles::<BaseElement>(table.len());
//     RowMatrix::interpolate_poly_concurrent(&mut table, &inv_twiddles);
//     // assert_eq!(interpolate_matrix.as_data(), matrix.as_data());
// }

// #[test]
// fn test_interpolate_poly_with_offset_matrix_concurrent() {
//     // degree 15
//     let n = 1024;
//     let num_polys = 16;

//     let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
//     let rows = transpose_concurrent(columns.clone());
//     let row_width = rows[0].len();
//     let mut flatten_rows = rows.into_iter().flatten().collect::<Vec<_>>();
//     let matrix = RowMatrix::new(&mut flatten_rows, row_width);

//     let offset = BaseElement::GENERATOR;
//     let domain = build_domain(n);
//     let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
//     for p in columns.iter_mut() {
//         *p = polynom::eval_many(p, &shifted_domain);
//     }
//     let eval_col = transpose_concurrent(columns);
//     let mut eval_cols_faltten = eval_col.into_iter().flatten().collect::<Vec<_>>();
//     let mut interpolate_matrix = RowMatrix::new(&mut eval_cols_faltten, row_width);

//     let inv_twiddles = get_inv_twiddles::<BaseElement>(matrix.len());
//     RowMatrix::interpolate_poly_with_offset_concurrent(
//         &mut interpolate_matrix,
//         &inv_twiddles,
//         offset,
//     );
//     assert_eq!(interpolate_matrix.as_data(), matrix.as_data());
// }

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a domain of size `size` using the primitive element of the field.
fn build_domain(size: usize) -> Vec<BaseElement> {
    let g = BaseElement::get_root_of_unity(log2(size));
    get_power_series(g, size)
}

/// Transposes a matrix stored in a column major format to a row major format.
/// fn transpose<E: FieldElement>(v: Vec<Vec<E>>) -> Vec<Vec<E>> {
fn transpose<E: FieldElement>(matrix: Vec<Vec<E>>) -> Vec<Vec<E>> {
    let num_rows = matrix.len();
    let num_cols = matrix[0].len();
    let mut result = vec![vec![E::ZERO; num_rows]; num_cols];
    result.iter_mut().enumerate().for_each(|(i, row)| {
        row.iter_mut().enumerate().for_each(|(j, col)| {
            *col = matrix[j][i];
        })
    });
    result
}

/// Transposes a matrix stored in a column major format to a row major format concurrently.
fn transpose_concurrent<E: FieldElement>(matrix: Vec<Vec<E>>) -> Vec<Vec<E>> {
    let num_rows = matrix.len();
    let num_cols = matrix[0].len();
    let mut result = vec![vec![E::ZERO; num_rows]; num_cols];
    result.par_iter_mut().enumerate().for_each(|(i, row)| {
        row.par_iter_mut().enumerate().for_each(|(j, col)| {
            *col = matrix[j][i];
        })
    });
    result
}

/// Build a vector of RowMatrix objects from a column major matrix.
fn build_row_matrix<E>(matrix: Vec<Vec<E>>) -> Vec<RowMatrix<E>>
where
    E: FieldElement,
{
    let num_of_segments = matrix.len() / ARR_SIZE;
    let mut row_matrices = Vec::with_capacity(num_of_segments);
    for i in 0..num_of_segments {
        let mut segment = matrix[i * ARR_SIZE..(i + 1) * ARR_SIZE].to_vec();
        let mut transpose_segment = transpose(segment);

        // convert transpose segment to a vector of arrays of elements.
        let row_matrix_data: Vec<[E; ARR_SIZE]> = transpose_segment
            .into_iter()
            .map(|vec| to_array(vec))
            .collect();

        let mut row_matrix = RowMatrix::new(row_matrix_data, ARR_SIZE);
        row_matrices.push(row_matrix);
    }
    row_matrices
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

/// Flattens a vector of RowMatrix objects into a slice. The slice is a row major representation of
/// the matrix.
fn flatten_row_matrix<E>(row_matrices: Vec<RowMatrix<E>>) -> Vec<E>
where
    E: FieldElement,
{
    let mut result = Vec::with_capacity(row_matrices.len() * row_matrices[0].len() * ARR_SIZE);
    let each_row_matrix_len = row_matrices[0].len();

    for i in 0..each_row_matrix_len {
        for row_matrix in &row_matrices {
            let row = row_matrix.get_row(i);
            result.extend_from_slice(row);
        }
    }
    result
}
