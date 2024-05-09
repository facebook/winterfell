// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use utils::uninit_vector;

use super::fft_inputs::FftInputs;
use crate::{field::StarkField, FieldElement};

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` in-place over the domain of length `p.len()` in the field specified
/// by `B` using the FFT algorithm.
pub fn evaluate_poly<B, E>(p: &mut [E], twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    p.fft_in_place(twiddles);
    p.permute();
}

/// Evaluates polynomial `p` over the domain of length `p.len()` * `blowup_factor` shifted by
/// `domain_offset` in the field specified `B` using the FFT algorithm and returns the result.
pub fn evaluate_poly_with_offset<B, E>(
    p: &[E],
    twiddles: &[B],
    domain_offset: B,
    blowup_factor: usize,
) -> Vec<E>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    let domain_size = p.len() * blowup_factor;
    let g = B::get_root_of_unity(domain_size.ilog2());
    let mut result = unsafe { uninit_vector(domain_size) };

    result.as_mut_slice().chunks_mut(p.len()).enumerate().for_each(|(i, chunk)| {
        let idx = super::permute_index(blowup_factor, i) as u64;
        let offset = g.exp(idx.into()) * domain_offset;
        let mut factor = E::BaseField::ONE;
        for (d, c) in chunk.iter_mut().zip(p.iter()) {
            *d = (*c).mul_base(factor);
            factor *= offset;
        }
        chunk.fft_in_place(twiddles);
    });

    result.permute();
    result
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Interpolates `evaluations` over a domain of length `evaluations.len()` in the field specified
/// `B` into a polynomial in coefficient form using the FFT algorithm.
///
/// # Panics
/// Panics if the length of `evaluations` is greater than [u32::MAX].
pub fn interpolate_poly<B, E>(evaluations: &mut [E], inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(evaluations.len() <= u32::MAX as usize, "too many evaluations");
    let inv_length = B::inv((evaluations.len() as u32).into());
    evaluations.fft_in_place(inv_twiddles);
    evaluations.shift_by(inv_length);
    evaluations.permute();
}

/// Interpolates `evaluations` over a domain of length `evaluations.len()` and shifted by
/// `domain_offset` in the field specified by `B` into a polynomial in coefficient form using
/// the FFT algorithm.
///
/// # Panics
/// Panics if the length of `evaluations` is greater than [u32::MAX].
pub fn interpolate_poly_with_offset<B, E>(
    evaluations: &mut [E],
    inv_twiddles: &[B],
    domain_offset: B,
) where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(evaluations.len() <= u32::MAX as usize, "too many evaluations");

    evaluations.fft_in_place(inv_twiddles);
    evaluations.permute();

    let domain_offset = B::inv(domain_offset);
    let offset = B::inv((evaluations.len() as u32).into());

    evaluations.shift_by_series(offset, domain_offset);
}
