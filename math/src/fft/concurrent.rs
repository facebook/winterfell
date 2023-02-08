// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::fft_inputs::FftInputs;
use crate::{
    field::{FieldElement, StarkField},
    utils::log2,
};
use rayon::prelude::*;
use utils::{collections::Vec, uninit_vector};

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` using FFT algorithm; the evaluation is done in-place, meaning
/// `p` is updated with results of the evaluation.
pub fn evaluate_poly<B: StarkField, E: FieldElement<BaseField = B>>(p: &mut [E], twiddles: &[B]) {
    p.split_radix_fft(twiddles);
    p.permute();
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
        .par_chunks_mut(p.len())
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = super::permute_index(blowup_factor, i) as u64;
            let offset = g.exp(idx.into()) * domain_offset;
            clone_and_shift(p, chunk, offset);
            chunk.split_radix_fft(twiddles);
        });

    result.permute();
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
    v.split_radix_fft(inv_twiddles);
    let inv_length = E::inv((v.len() as u64).into());
    v.par_iter_mut().for_each(|e| *e *= inv_length);
    v.permute();
}

/// Uses FFT algorithm to interpolate a polynomial from provided `values` over the domain defined
/// by `inv_twiddles` and offset by `domain_offset` factor.
pub fn interpolate_poly_with_offset<B, E>(values: &mut [E], inv_twiddles: &[B], domain_offset: B)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    values.split_radix_fft(inv_twiddles);
    values.permute();

    let domain_offset = E::BaseField::inv(domain_offset);
    let inv_len = E::BaseField::inv((values.len() as u64).into());
    let batch_size = values.len()
        / rayon::current_num_threads()
            .next_power_of_two()
            .min(values.len());

    values
        .par_chunks_mut(batch_size)
        .enumerate()
        .for_each(|(i, batch)| {
            let offset = domain_offset.exp(((i * batch_size) as u64).into()) * inv_len;
            batch.shift_by_series(offset, domain_offset, 0);
        });
}

// HELPER FUNCTIONS
// ================================================================================================

fn clone_and_shift<E: FieldElement>(source: &[E], destination: &mut [E], offset: E::BaseField) {
    let batch_size = source.len()
        / rayon::current_num_threads()
            .next_power_of_two()
            .min(source.len());
    source
        .par_chunks(batch_size)
        .zip(destination.par_chunks_mut(batch_size))
        .enumerate()
        .for_each(|(i, (source, destination))| {
            let mut factor = offset.exp(((i * batch_size) as u64).into());
            for (s, d) in source.iter().zip(destination.iter_mut()) {
                *d = (*s).mul_base(factor);
                factor *= offset;
            }
        });
}
