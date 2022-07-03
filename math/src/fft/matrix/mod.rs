// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    arrays::matrix::Matrix,
    field::{FieldElement, StarkField},
    utils::log2,
};

#[cfg(feature = "concurrent")]
use std::marker::{Send, Sync};

mod serial;

#[cfg(feature = "concurrent")]
mod concurrent;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================
#[allow(dead_code)]
const MIN_CONCURRENT_SIZE: usize = 1024;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates a polynomial on all points of the specified (shifted) domain using the FFT algorithm.

#[cfg(not(feature = "concurrent"))]
pub fn evaluate_poly_with_offset<B, E, M>(
    p: &M,
    twiddles: &[B],
    domain_offset: B,
    blowup_factor: usize,
) -> M
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E>,
{
    assert!(
        p.num_rows().is_power_of_two(),
        "number of coefficients must be a power of 2"
    );
    assert!(
        blowup_factor.is_power_of_two(),
        "blowup factor must be a power of 2"
    );
    assert_eq!(
        p.num_rows(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        p.num_rows() / 2,
        twiddles.len()
    );
    assert!(
        log2(p.num_rows() * blowup_factor) <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        p.num_rows() * blowup_factor
    );
    assert_ne!(domain_offset, B::ZERO, "domain offset cannot be zero");

    // assign a dummy value here to make the compiler happy
    #[allow(unused_assignments)]
    let mut result = M::new();

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    result = serial::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);

    result
}

#[cfg(feature = "concurrent")]
pub fn evaluate_poly_with_offset<B, E, M>(
    p: &M,
    twiddles: &[B],
    domain_offset: B,
    blowup_factor: usize,
) -> M
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E> + Send + Sync,
{
    assert!(
        p.num_rows().is_power_of_two(),
        "number of coefficients must be a power of 2"
    );
    assert!(
        blowup_factor.is_power_of_two(),
        "blowup factor must be a power of 2"
    );
    assert_eq!(
        p.num_rows(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        p.num_rows() / 2,
        twiddles.len()
    );
    assert!(
        log2(p.num_rows() * blowup_factor) <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        p.num_rows() * blowup_factor
    );
    assert_ne!(domain_offset, B::ZERO, "domain offset cannot be zero");

    // assign a dummy value here to make the compiler happy
    #[allow(unused_assignments)]
    let mut result = M::new();

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if p.num_rows() >= MIN_CONCURRENT_SIZE {
        result = concurrent::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);
    } else {
        result = serial::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);
    }

    result
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Interpolates evaluations of a polynomial over the specified domain into a polynomial in
/// coefficient from using the FFT algorithm.
#[cfg(not(feature = "concurrent"))]
pub fn interpolate_poly<B, E, M>(evaluations: &mut M, inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E>,
{
    assert!(
        evaluations.num_rows().is_power_of_two(),
        "number of evaluations must be a power of 2, but was {}",
        evaluations.num_rows()
    );
    assert_eq!(
        evaluations.num_rows(),
        inv_twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        evaluations.num_rows() / 2,
        inv_twiddles.len()
    );
    assert!(
        log2(evaluations.num_rows()) <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        evaluations.num_rows()
    );

    // when `concurrent` feature is enabled, run the concurrent version of interpolate_poly;
    // unless the number of evaluations is small, then don't bother with the concurrent version
    serial::interpolate_poly(evaluations, inv_twiddles);
}

#[cfg(feature = "concurrent")]
pub fn interpolate_poly<B, E, M>(evaluations: &mut M, inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E> + Send + Sync,
{
    assert!(
        evaluations.num_rows().is_power_of_two(),
        "number of evaluations must be a power of 2, but was {}",
        evaluations.num_rows()
    );
    assert_eq!(
        evaluations.num_rows(),
        inv_twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        evaluations.num_rows() / 2,
        inv_twiddles.len()
    );
    assert!(
        log2(evaluations.num_rows()) <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        evaluations.num_rows()
    );

    // when `concurrent` feature is enabled, run the concurrent version of interpolate_poly;
    // unless the number of evaluations is small, then don't bother with the concurrent version
    if evaluations.num_rows() >= MIN_CONCURRENT_SIZE {
        concurrent::interpolate_poly(evaluations, inv_twiddles);
    } else {
        serial::interpolate_poly(evaluations, inv_twiddles);
    }
}
