// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{f128::BaseElement, FieldElement, StarkField},
    polynom,
    utils::{get_power_series, log2},
};
use utils::AsBytes;

// POLYNOMIAL EVALUATION
// ================================================================================================

#[test]
fn fft_evaluate_poly() {
    let n = super::MIN_CONCURRENT_SIZE * 2;
    let mut p = build_random_element_vec(n);

    let domain = build_domain(n);
    let expected = polynom::eval_many(&p, &domain);

    let twiddles = super::get_twiddles::<BaseElement>(n);
    super::evaluate_poly(&mut p, &twiddles);
    assert_eq!(expected, p);
}

#[test]
fn fft_evaluate_poly_with_offset() {
    let offset = BaseElement::GENERATOR;
    let blowup_factor = 2;
    let m = super::MIN_CONCURRENT_SIZE * 2;
    let n = m * blowup_factor;

    let p = BaseElement::prng_vector([1; 32], m);

    let domain = build_domain(n);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
    let expected = polynom::eval_many(&p, &shifted_domain);

    let twiddles = super::get_twiddles::<BaseElement>(m);
    let actual = super::evaluate_poly_with_offset(&p, &twiddles, offset, blowup_factor);
    assert_eq!(expected, actual);
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

#[test]
fn fft_interpolate_poly() {
    let n = super::MIN_CONCURRENT_SIZE * 2;
    let expected: Vec<BaseElement> = build_random_element_vec(n);

    let domain = build_domain(n);
    let mut ys = polynom::eval_many(&expected, &domain);

    let inv_twiddles = super::get_inv_twiddles::<BaseElement>(n);
    super::interpolate_poly(&mut ys, &inv_twiddles);
    assert_eq!(expected, ys);
}

#[test]
fn fft_interpolate_poly_with_offset() {
    let offset = BaseElement::GENERATOR;
    let n = super::MIN_CONCURRENT_SIZE * 2;
    let expected: Vec<BaseElement> = build_random_element_vec(n);

    let domain = build_domain(n);
    let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
    let mut ys = polynom::eval_many(&expected, &shifted_domain);

    let inv_twiddles = super::get_inv_twiddles::<BaseElement>(n);
    super::interpolate_poly_with_offset(&mut ys, &inv_twiddles, offset);
    assert_eq!(expected, ys);
}

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
