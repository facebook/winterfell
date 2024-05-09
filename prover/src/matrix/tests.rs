// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use rand_utils::rand_vector;

use crate::{
    math::{fields::f64::BaseElement, get_power_series, polynom, StarkField},
    ColMatrix, RowMatrix,
};

#[test]
fn test_eval_poly_with_offset_matrix() {
    let n = 256;
    let num_polys = 64;
    let blowup_factor = 8;

    // generate random columns. Each column is a polynomial of degree n - 1.
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();

    // evaluate columns using the row matrix implementation.
    let row_matrix =
        RowMatrix::evaluate_polys::<8>(&ColMatrix::new(columns.clone()), blowup_factor);

    // evaluate columns using the using the polynomial evaluation implementation.
    let offset = BaseElement::GENERATOR;
    let domain = build_domain(n * blowup_factor);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
    for p in columns.iter_mut() {
        *p = polynom::eval_many(p, &shifted_domain);
    }

    // compare the results of the two implementations row by row.
    for row in 0..n * blowup_factor {
        let row_matrix_row = row_matrix.row(row);
        let eval_col_row = get_row(&columns, row);
        assert_eq!(row_matrix_row, eval_col_row);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a domain of size `size` using the primitive element of the field.
fn build_domain(size: usize) -> Vec<BaseElement> {
    let g = BaseElement::get_root_of_unity(size.ilog2());
    get_power_series(g, size)
}

/// Returns a row of the column major matrix.
fn get_row(columns: &[Vec<BaseElement>], row_id: usize) -> Vec<BaseElement> {
    columns.iter().map(|col| col[row_id]).collect()
}
