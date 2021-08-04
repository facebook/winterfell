// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{f128::BaseElement, FieldElement, StarkField},
    polynom,
    utils::{get_power_series, log2},
};
use utils::{collections::Vec, AsBytes};

// CORE ALGORITHMS
// ================================================================================================

#[test]
fn fft_in_place() {
    // degree 3
    let n = 4;
    let mut p = build_random_element_vec(n);
    let domain = build_domain(n);
    let expected = polynom::eval_many(&p, &domain);
    let twiddles = super::get_twiddles::<BaseElement>(n);
    super::serial::fft_in_place(&mut p, &twiddles, 1, 1, 0);
    super::permute(&mut p);
    assert_eq!(expected, p);

    // degree 7
    let n = 8;
    let mut p = build_random_element_vec(n);
    let domain = build_domain(n);
    let twiddles = super::get_twiddles::<BaseElement>(n);
    let expected = polynom::eval_many(&p, &domain);
    super::serial::fft_in_place(&mut p, &twiddles, 1, 1, 0);
    super::permute(&mut p);
    assert_eq!(expected, p);

    // degree 15
    let n = 16;
    let mut p = build_random_element_vec(n);
    let domain = build_domain(n);
    let twiddles = super::get_twiddles::<BaseElement>(16);
    let expected = polynom::eval_many(&p, &domain);
    super::serial::fft_in_place(&mut p, &twiddles, 1, 1, 0);
    super::permute(&mut p);
    assert_eq!(expected, p);

    // degree 1023
    let n = 1024;
    let mut p = build_random_element_vec(n);
    let domain = build_domain(n);
    let expected = polynom::eval_many(&p, &domain);
    let twiddles = super::get_twiddles::<BaseElement>(n);
    super::serial::fft_in_place(&mut p, &twiddles, 1, 1, 0);
    super::permute(&mut p);
    assert_eq!(expected, p);
}

#[test]
fn fft_get_twiddles() {
    let n = super::MIN_CONCURRENT_SIZE * 2;
    let g = BaseElement::get_root_of_unity(log2(n));

    let mut expected = get_power_series(g, n / 2);
    super::permute(&mut expected);

    let twiddles = super::get_twiddles::<BaseElement>(n);
    assert_eq!(expected, twiddles);
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_seed() -> [u8; 32] {
    let mut result = [0; 32];
    let seed = BaseElement::rand().as_bytes().to_vec();
    result[..16].copy_from_slice(&seed);
    result
}

fn build_random_element_vec(size: usize) -> Vec<BaseElement> {
    BaseElement::prng_vector(build_seed(), size)
}

fn build_domain(size: usize) -> Vec<BaseElement> {
    let g = BaseElement::get_root_of_unity(log2(size));
    get_power_series(g, size)
}
