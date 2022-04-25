// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{FieldElement, StarkField},
    utils::log2,
};
use utils::{collections::Vec, uninit_vector};

// CONSTANTS
// ================================================================================================
const MAX_LOOP: usize = 256;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` in-place over the domain of length `p.len()` in the field specified
/// by `B` using the FFT algorithm.
pub fn evaluate_poly<B, E>(p: &mut [E], twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fft_in_place(p, twiddles, 1, 1, 0);
    permute(p);
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
    let g = B::get_root_of_unity(log2(domain_size));
    let mut result = unsafe { uninit_vector(domain_size) };

    result
        .as_mut_slice()
        .chunks_mut(p.len())
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = super::permute_index(blowup_factor, i) as u64;
            let offset = g.exp(idx.into()) * domain_offset;
            let mut factor = E::BaseField::ONE;
            for (d, c) in chunk.iter_mut().zip(p.iter()) {
                *d = (*c).mul_base(factor);
                factor *= offset;
            }
            fft_in_place(chunk, twiddles, 1, 1, 0);
        });

    permute(&mut result);
    result
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Interpolates `evaluations` over a domain of length `evaluations.len()` in the field specified
/// `B` into a polynomial in coefficient form using the FFT algorithm.
pub fn interpolate_poly<B, E>(evaluations: &mut [E], inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fft_in_place(evaluations, inv_twiddles, 1, 1, 0);
    let inv_length = E::inv((evaluations.len() as u64).into());
    for e in evaluations.iter_mut() {
        *e *= inv_length;
    }
    permute(evaluations);
}

/// Interpolates `evaluations` over a domain of length `evaluations.len()` and shifted by
/// `domain_offset` in the field specified by `B` into a polynomial in coefficient form using
/// the FFT algorithm.
pub fn interpolate_poly_with_offset<B, E>(
    evaluations: &mut [E],
    inv_twiddles: &[B],
    domain_offset: B,
) where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fft_in_place(evaluations, inv_twiddles, 1, 1, 0);
    permute(evaluations);

    let domain_offset = E::inv(domain_offset.into());
    let mut offset = E::inv((evaluations.len() as u64).into());
    for coeff in evaluations.iter_mut() {
        *coeff *= offset;
        offset *= domain_offset;
    }
}

// PERMUTATIONS
// ================================================================================================

pub fn permute<T>(values: &mut [T]) {
    let n = values.len();
    for i in 0..n {
        let j = super::permute_index(n, i);
        if j > i {
            values.swap(i, j);
        }
    }
}

// CORE FFT ALGORITHM
// ================================================================================================

/// In-place recursive FFT with permuted output.
///
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
pub(super) fn fft_in_place<B, E>(
    values: &mut [E],
    twiddles: &[B],
    count: usize,
    stride: usize,
    offset: usize,
) where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    let size = values.len() / stride;
    debug_assert!(size.is_power_of_two());
    debug_assert!(offset < stride);
    debug_assert_eq!(values.len() % size, 0);

    // Keep recursing until size is 2
    if size > 2 {
        if stride == count && count < MAX_LOOP {
            fft_in_place(values, twiddles, 2 * count, 2 * stride, offset);
        } else {
            fft_in_place(values, twiddles, count, 2 * stride, offset);
            fft_in_place(values, twiddles, count, 2 * stride, offset + stride);
        }
    }

    for offset in offset..(offset + count) {
        butterfly(values, offset, stride);
    }

    let last_offset = offset + size * stride;
    for (i, offset) in (offset..last_offset)
        .step_by(2 * stride)
        .enumerate()
        .skip(1)
    {
        for j in offset..(offset + count) {
            butterfly_twiddle(values, twiddles[i], j, stride);
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn butterfly<E>(values: &mut [E], offset: usize, stride: usize)
where
    E: FieldElement,
{
    let i = offset;
    let j = offset + stride;
    let temp = values[i];
    values[i] = temp + values[j];
    values[j] = temp - values[j];
}

#[inline(always)]
fn butterfly_twiddle<B, E>(values: &mut [E], twiddle: B, offset: usize, stride: usize)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    let i = offset;
    let j = offset + stride;
    let temp = values[i];
    values[j] = values[j].mul_base(twiddle);
    values[i] = temp + values[j];
    values[j] = temp - values[j];
}
