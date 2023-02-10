// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    math::{
        fft::fft_inputs::FftInputs, fields::f64::BaseElement, get_power_series, log2, polynom,
        StarkField,
    },
    Matrix, Segments,
};

use super::ARR_SIZE;
use math::FieldElement;
use rand_utils::rand_vector;

use utils::collections::Vec;

#[test]
fn test_eval_poly_with_offset_matrix() {
    let n = 256;
    let num_polys = 64;
    let blowup_factor = 8;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    let segment = Segments::from_polys(&Matrix::new(columns.clone()), blowup_factor);
    // segment.transpose_to_gpu_friendly_matrix();
    let result_data = flatten_row_matrix(segment);

    let offset = BaseElement::GENERATOR;
    let domain = build_domain(n * blowup_factor);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &shifted_domain);
    }
    let eval_col = transpose(columns);
    let eval_cols_flatten = eval_col.into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(eval_cols_flatten, result_data);
}

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

/// Flattens a vector of RowMatrix objects into a slice. The slice is a row major representation of
/// the matrix.
fn flatten_row_matrix<E>(row_matrices: Segments<E>) -> Vec<E>
where
    E: FieldElement,
{
    let mut result = Vec::with_capacity(
        row_matrices.len() * row_matrices.get(0).expect("Error").len() * ARR_SIZE,
    );
    let each_row_matrix_len = row_matrices.get(0).expect("Error").len();

    for i in 0..each_row_matrix_len {
        for row_matrix in row_matrices.iter() {
            let row = row_matrix.get_row(i);
            result.extend_from_slice(row);
        }
    }
    result
}
