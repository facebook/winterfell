// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{FieldElement, StarkField},
    utils,
};

mod serial;

#[cfg(feature = "concurrent")]
mod concurrent;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================
const USIZE_BITS: usize = 0_usize.count_zeros() as usize;
pub const MIN_CONCURRENT_SIZE: usize = 1024;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` using FFT algorithm; the evaluation is done in-place, meaning
/// `p` is updated with results of the evaluation.
///
/// When `concurrent` feature is enabled, the evaluation uses as many threads as are
/// available in Rayon's global thread pool (usually as many threads as logical cores).
/// Otherwise, the evaluation is done in a single thread.
pub fn evaluate_poly<B: StarkField, E: FieldElement<BaseField = B>>(p: &mut [E], twiddles: &[B]) {
    assert!(
        p.len().is_power_of_two(),
        "number of coefficients must be a power of 2"
    );
    assert_eq!(
        p.len(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        p.len() / 2,
        twiddles.len()
    );

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && p.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::evaluate_poly(p, twiddles);
    } else {
        serial::evaluate_poly(p, twiddles);
    }
}

/// Evaluates polynomial `p` using FFT algorithm and returns the result. The polynomial is
/// evaluated over domain specified by `twiddles`, expanded by the `blowup_factor`, and shifted
/// by the `domain_offset`.
///
/// When `concurrent` feature is enabled, the evaluation uses as many threads as are
/// available in Rayon's global thread pool (usually as many threads as logical cores).
/// Otherwise, the evaluation is done in a single thread.
pub fn evaluate_poly_with_offset<B: StarkField, E: FieldElement<BaseField = B>>(
    p: &[E],
    twiddles: &[B],
    domain_offset: B,
    blowup_factor: usize,
) -> Vec<E> {
    assert!(
        p.len().is_power_of_two(),
        "number of coefficients must be a power of 2"
    );
    assert!(
        blowup_factor.is_power_of_two(),
        "blowup factor must be a power of 2"
    );
    assert_eq!(
        p.len(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        p.len() / 2,
        twiddles.len()
    );

    // assign a dummy value here to make the compiler happy
    #[allow(unused_assignments)]
    let mut result = Vec::new();

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && p.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        {
            result =
                concurrent::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);
        }
    } else {
        result = serial::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);
    }

    result
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Uses FFT algorithm to interpolate a polynomial from provided `values`; the interpolation
/// is done in-place, meaning `values` are updated with polynomial coefficients.
///
/// When `concurrent` feature is enabled, the interpolation uses as many threads as are
/// available in Rayon's global thread pool (usually as many threads as logical cores).
/// Otherwise, the interpolation is done in a single thread.
pub fn interpolate_poly<B, E>(values: &mut [E], inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    debug_assert!(
        values.len().is_power_of_two(),
        "number of values must be a power of 2, but was {}",
        values.len()
    );
    assert_eq!(
        values.len(),
        inv_twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        values.len() / 2,
        inv_twiddles.len()
    );

    // when `concurrent` feature is enabled, run the concurrent version of interpolate_poly;
    // unless the number of evaluations is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && values.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::interpolate_poly(values, inv_twiddles);
    } else {
        serial::interpolate_poly(values, inv_twiddles);
    }
}

/// Uses FFT algorithm to interpolate a polynomial from provided `values` over the domain defined
/// by `inv_twiddles` and offset by `domain_offset` factor.
///
/// When `concurrent` feature is enabled, interpolation is done using as many threads as are
/// available in Rayon's global thread pool (usually as many threads as logical cores).
/// Otherwise, the interpolation is done in a single thread.
pub fn interpolate_poly_with_offset<B, E>(values: &mut [E], inv_twiddles: &[B], domain_offset: B)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    debug_assert!(
        values.len().is_power_of_two(),
        "number of values must be a power of 2, but was {}",
        values.len()
    );
    assert_eq!(
        values.len(),
        inv_twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        values.len() / 2,
        inv_twiddles.len()
    );

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && values.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::interpolate_poly_with_offset(values, inv_twiddles, domain_offset);
    } else {
        serial::interpolate_poly_with_offset(values, inv_twiddles, domain_offset);
    }
}

// TWIDDLES
// ================================================================================================

/// Returns a set of twiddles for the specified domain size. These twiddles can then be used for
/// FFT-based polynomial evaluation.
///
/// When `concurrent` feature is enabled, twiddles are generated using as many threads as are
/// available in Rayon's global thread pool (usually as many threads as logical cores).
/// Otherwise, the twiddles are generated in a single thread.
pub fn get_twiddles<B: StarkField>(domain_size: usize) -> Vec<B> {
    debug_assert!(
        domain_size.is_power_of_two(),
        "domain size must be a power of 2"
    );
    let root = B::get_root_of_unity(utils::log2(domain_size));
    let mut twiddles = utils::get_power_series(root, domain_size / 2);
    permute(&mut twiddles);
    twiddles
}

/// Returns a set of inverse twiddles for the specified domain size. These twiddles can then be
/// used for FFT-based polynomial interpolation.
///
/// When `concurrent` feature is enabled, twiddles are generated using as many threads as are
/// available in Rayon's global thread pool (usually as many threads as logical cores).
/// Otherwise, the twiddles are generated in a single thread.
pub fn get_inv_twiddles<B: StarkField>(domain_size: usize) -> Vec<B> {
    debug_assert!(
        domain_size.is_power_of_two(),
        "domain size must be a power of 2"
    );
    let root = B::get_root_of_unity(utils::log2(domain_size));
    let inv_root = root.exp((domain_size as u32 - 1).into());
    let mut inv_twiddles = utils::get_power_series(inv_root, domain_size / 2);
    permute(&mut inv_twiddles);
    inv_twiddles
}

// DEGREE INFERENCE
// ================================================================================================

/// Determines degree of a polynomial implied by the provided evaluations.
pub fn infer_degree<B, E>(evaluations: &[E], domain_offset: B) -> usize
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(
        evaluations.len().is_power_of_two(),
        "number of evaluations must be a power of 2"
    );
    let mut poly = evaluations.to_vec();
    let inv_twiddles = get_inv_twiddles::<B>(evaluations.len());
    interpolate_poly_with_offset(&mut poly, &inv_twiddles, domain_offset);
    super::polynom::degree_of(&poly)
}

// HELPER FUNCTIONS
// ================================================================================================

fn permute<E: FieldElement>(v: &mut [E]) {
    if cfg!(feature = "concurrent") && v.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::permute(v);
    } else {
        serial::permute(v);
    }
}

fn permute_index(size: usize, index: usize) -> usize {
    debug_assert!(index < size);
    if size == 1 {
        return 0;
    }
    debug_assert!(size.is_power_of_two());
    let bits = size.trailing_zeros() as usize;
    index.reverse_bits() >> (USIZE_BITS - bits)
}
