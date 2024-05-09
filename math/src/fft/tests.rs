// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use rand_utils::rand_vector;

use crate::{
    fft::fft_inputs::FftInputs,
    field::{f128::BaseElement, StarkField},
    polynom,
    utils::get_power_series,
};

// CORE ALGORITHMS
// ================================================================================================

#[test]
fn fft_in_place() {
    // degree 3
    let n = 4;
    let mut p = rand_vector(n);
    let domain = build_domain(n);
    let expected = polynom::eval_many(&p, &domain);
    let twiddles = super::get_twiddles::<BaseElement>(n);
    p.fft_in_place(&twiddles);
    p.permute();
    assert_eq!(expected, p);

    // degree 7
    let n = 8;
    let mut p = rand_vector(n);
    let domain = build_domain(n);
    let twiddles = super::get_twiddles::<BaseElement>(n);
    let expected = polynom::eval_many(&p, &domain);
    p.fft_in_place(&twiddles);
    p.permute();
    assert_eq!(expected, p);

    // degree 15
    let n = 16;
    let mut p = rand_vector(n);
    let domain = build_domain(n);
    let twiddles = super::get_twiddles::<BaseElement>(16);
    let expected = polynom::eval_many(&p, &domain);
    p.fft_in_place(&twiddles);
    p.permute();
    assert_eq!(expected, p);

    // degree 1023
    let n = 1024;
    let mut p = rand_vector(n);
    let domain = build_domain(n);
    let expected = polynom::eval_many(&p, &domain);
    let twiddles = super::get_twiddles::<BaseElement>(n);
    p.fft_in_place(&twiddles);
    p.permute();
    assert_eq!(expected, p);
}

#[test]
fn fft_get_twiddles() {
    let n = super::MIN_CONCURRENT_SIZE * 2;
    let g = BaseElement::get_root_of_unity(n.ilog2());

    let mut expected = get_power_series(g, n / 2);
    expected.permute();

    let twiddles = super::get_twiddles::<BaseElement>(n);
    assert_eq!(expected, twiddles);
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_domain(size: usize) -> Vec<BaseElement> {
    let g = BaseElement::get_root_of_unity(size.ilog2());
    get_power_series(g, size)
}
