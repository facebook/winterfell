// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{FieldElement, StarkField},
    utils::log2,
};
use utils::uninit_vector;

// CONSTANTS
// ================================================================================================
const MAX_LOOP: usize = 256;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` using FFT algorithm; the evaluation is done in-place, meaning
/// `p` is updated with results of the evaluation.
pub fn evaluate_poly<B: StarkField, E: FieldElement<BaseField = B>>(p: &mut [E], twiddles: &[B]) {
    fft_in_place(p, twiddles, 1, 1, 0);
    permute(p);
}

/// Evaluates polynomial `p` using FFT algorithm and returns the result. The polynomial is
/// evaluated over domain specified by `twiddles`, expanded by the `blowup_factor`, and shifted
/// by the `domain_offset`.
pub fn evaluate_poly_with_offset<B: StarkField, E: FieldElement<BaseField = B>>(
    p: &[E],
    twiddles: &[B],
    domain_offset: B,
    blowup_factor: usize,
) -> Vec<E> {
    let domain_size = p.len() * blowup_factor;
    let g = B::get_root_of_unity(log2(domain_size));
    let mut result = unsafe { uninit_vector(domain_size) };

    result
        .as_mut_slice()
        .chunks_mut(p.len())
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = super::permute_index(blowup_factor, i) as u64;
            let offset = E::from(g.exp(idx.into()) * domain_offset);
            let mut factor = E::ONE;
            for (d, c) in chunk.iter_mut().zip(p.iter()) {
                *d = *c * factor;
                factor *= offset;
            }
            fft_in_place(chunk, twiddles, 1, 1, 0);
        });

    permute(&mut result);
    result
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Uses FFT algorithm to interpolate a polynomial from provided `values`; the interpolation
/// is done in-place, meaning `values` are updated with polynomial coefficients.
pub fn interpolate_poly<B, E>(v: &mut [E], inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fft_in_place(v, inv_twiddles, 1, 1, 0);
    let inv_length = E::inv((v.len() as u64).into());
    for e in v.iter_mut() {
        *e *= inv_length;
    }
    permute(v);
}

/// Uses FFT algorithm to interpolate a polynomial from provided `values` over the domain defined
/// by `inv_twiddles` and offset by `domain_offset` factor.
pub fn interpolate_poly_with_offset<B, E>(values: &mut [E], inv_twiddles: &[B], domain_offset: B)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fft_in_place(values, inv_twiddles, 1, 1, 0);
    permute(values);

    let domain_offset = E::inv(domain_offset.into());
    let mut offset = E::inv((values.len() as u64).into());
    for coeff in values.iter_mut() {
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

// RAW FFT FUNCTION
// ================================================================================================

/// Executes the FFT algorithm against the provided `values` using the provided `twiddles`.
pub fn fft<B: StarkField, E: FieldElement<BaseField = B>>(values: &mut [E], twiddles: &[B]) {
    debug_assert!(values.len().is_power_of_two());
    debug_assert_eq!(values.len() / 2, twiddles.len());
    fft_in_place(values, twiddles, 1, 1, 0);
    permute(values);
}

// CORE FFT ALGORITHM
// ================================================================================================

/// In-place recursive FFT with permuted output.
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
pub(super) fn fft_in_place<B: StarkField, E: FieldElement<BaseField = B>>(
    values: &mut [E],
    twiddles: &[B],
    count: usize,
    stride: usize,
    offset: usize,
) {
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
fn butterfly<E: FieldElement>(values: &mut [E], offset: usize, stride: usize) {
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
    values[j] *= E::from(twiddle);
    values[i] = temp + values[j];
    values[j] = temp - values[j];
}
