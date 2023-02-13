// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    math::{fields::f64::BaseElement, get_power_series, log2, polynom, StarkField},
    Matrix, RowMatrix,
};
use math::FieldElement;
use rand_utils::rand_vector;
use utils::collections::Vec;

#[test]
fn test_eval_poly_with_offset_matrix() {
    let n = 256;
    let num_polys = 64;
    let blowup_factor = 8;

    // generate random columns. Each column is a polynomial of degree n - 1.
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    // evaluate columns using the row matrix implementation.
    let row_matrix = RowMatrix::from_polys(&Matrix::new(columns.clone()), blowup_factor);

    // evaluate columns using the using the polynomial evaluation implementation.
    let offset = BaseElement::GENERATOR;
    let domain = build_domain(n * blowup_factor);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &shifted_domain);
    }

    // transpose the columns back to a row major format.
    let eval_col = transpose(columns);

    // compare the results
    assert_eq!(row_matrix.as_data(), eval_col);
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a domain of size `size` using the primitive element of the field.
fn build_domain(size: usize) -> Vec<BaseElement> {
    let g = BaseElement::get_root_of_unity(log2(size));
    get_power_series(g, size)
}

/// Transposes a matrix stored in a column major format to a row major format.
fn transpose<E: FieldElement>(matrix: Vec<Vec<E>>) -> Vec<E> {
    // fetch the number of rows and columns in the column-major matrix.
    let row_len = matrix.len();
    let num_rows = matrix[0].len();

    // allocate a vector to store the transposed matrix.
    let mut result = vec![E::ZERO; num_rows * row_len];

    // transpose the matrix.
    matrix.iter().enumerate().for_each(|(i, row)| {
        row.iter().enumerate().for_each(|(j, col)| {
            result[j * row_len + i] = *col;
        })
    });

    result
}
