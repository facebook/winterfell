// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{f128::BaseElement, StarkField},
    polynom,
    utils::{get_power_series, log2},
    Matrix, RowMajorTable,
};
use rand_utils::rand_vector;
use utils::collections::Vec;

// CORE ALGORITHMS
// ================================================================================================

#[test]
fn fft_in_place_matrix() {
    // degree 3
    let n = 4;
    let num_polys = 10;
    let mut columns: Vec<Vec<BaseElement>> = (0..num_polys).map(|_| rand_vector(n)).collect();
    let mut table = RowMajorTable::from_columns(columns.clone());
    let domain = build_domain(n);
    for p in columns.iter_mut() {
        *p = polynom::eval_many(&p, &domain);
    }
    let twiddles = super::super::get_twiddles::<BaseElement>(n);
    super::serial::fft_in_place(&mut table, &twiddles, 1, 1, 0);
    super::serial::permute(&mut table);
    assert_eq!(RowMajorTable::from_columns(columns).data(), table.data());
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_domain(size: usize) -> Vec<BaseElement> {
    let g = BaseElement::get_root_of_unity(log2(size));
    get_power_series(g, size)
}
