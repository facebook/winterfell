// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    field::{FieldElement, StarkField},
    utils::log2,
};
use utils::{collections::Vec, iterators::*, rayon, uninit_vector};

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` using FFT algorithm; the evaluation is done in-place, meaning
/// `p` is updated with results of the evaluation.
pub fn evaluate_poly<B: StarkField, E: FieldElement<BaseField = B>>(p: &mut [E], twiddles: &[B]) {
    split_radix_fft(p, twiddles);
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
        .par_chunks_mut(p.len())
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = super::permute_index(blowup_factor, i) as u64;
            let offset = g.exp(idx.into()) * domain_offset;
            clone_and_shift(p, chunk, offset);
            split_radix_fft(chunk, twiddles);
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
    split_radix_fft(v, inv_twiddles);
    let inv_length = E::inv((v.len() as u64).into());
    v.par_iter_mut().for_each(|e| *e *= inv_length);
    permute(v);
}

/// Uses FFT algorithm to interpolate a polynomial from provided `values` over the domain defined
/// by `inv_twiddles` and offset by `domain_offset` factor.
pub fn interpolate_poly_with_offset<B, E>(values: &mut [E], inv_twiddles: &[B], domain_offset: B)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    split_radix_fft(values, inv_twiddles);
    permute(values);

    let domain_offset = E::inv(domain_offset.into());
    let inv_len = E::inv((values.len() as u64).into());
    let batch_size = values.len() / rayon::current_num_threads().next_power_of_two();

    values
        .par_chunks_mut(batch_size)
        .enumerate()
        .for_each(|(i, batch)| {
            let mut offset = domain_offset.exp(((i * batch_size) as u64).into()) * inv_len;
            for coeff in batch.iter_mut() {
                *coeff = *coeff * offset;
                offset = offset * domain_offset;
            }
        });
}

// PERMUTATIONS
// ================================================================================================

pub fn permute<E: FieldElement>(v: &mut [E]) {
    let n = v.len();
    let num_batches = rayon::current_num_threads().next_power_of_two();
    let batch_size = n / num_batches;
    rayon::scope(|s| {
        for batch_idx in 0..num_batches {
            // create another mutable reference to the slice of values to use in a new thread; this
            // is OK because we never write the same positions in the slice from different threads
            let values = unsafe { &mut *(&mut v[..] as *mut [E]) };
            s.spawn(move |_| {
                let batch_start = batch_idx * batch_size;
                let batch_end = batch_start + batch_size;
                for i in batch_start..batch_end {
                    let j = super::permute_index(n, i);
                    if j > i {
                        values.swap(i, j);
                    }
                }
            });
        }
    });
}

// SPLIT-RADIX FFT
// ================================================================================================

/// In-place recursive FFT with permuted output.
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
pub(super) fn split_radix_fft<B: StarkField, E: FieldElement<BaseField = B>>(
    values: &mut [E],
    twiddles: &[B],
) {
    // generator of the domain should be in the middle of twiddles
    let n = values.len();
    let g = twiddles[twiddles.len() / 2];
    debug_assert_eq!(g.exp((n as u32).into()), E::BaseField::ONE);

    let inner_len = 1_usize << (log2(n) / 2);
    let outer_len = n / inner_len;
    let stretch = outer_len / inner_len;
    debug_assert!(outer_len == inner_len || outer_len == 2 * inner_len);
    debug_assert_eq!(outer_len * inner_len, n);

    // transpose inner x inner x stretch square matrix
    transpose_square_stretch(values, inner_len, stretch);

    // apply inner FFTs
    values
        .par_chunks_mut(outer_len)
        .for_each(|row| super::serial::fft_in_place(row, &twiddles, stretch, stretch, 0));

    // transpose inner x inner x stretch square matrix
    transpose_square_stretch(values, inner_len, stretch);

    // apply outer FFTs
    values
        .par_chunks_mut(outer_len)
        .enumerate()
        .for_each(|(i, row)| {
            if i > 0 {
                let i = super::permute_index(inner_len, i);
                let inner_twiddle = g.exp((i as u32).into());
                let mut outer_twiddle = inner_twiddle;
                for element in row.iter_mut().skip(1) {
                    *element = (*element).mul_base(outer_twiddle);
                    outer_twiddle = outer_twiddle * inner_twiddle;
                }
            }
            super::serial::fft_in_place(row, &twiddles, 1, 1, 0)
        });
}

// TRANSPOSING
// ================================================================================================

fn transpose_square_stretch<T>(matrix: &mut [T], size: usize, stretch: usize) {
    assert_eq!(matrix.len(), size * size * stretch);
    match stretch {
        1 => transpose_square_1(matrix, size),
        2 => transpose_square_2(matrix, size),
        _ => unimplemented!("only stretch sizes 1 and 2 are supported"),
    }
}

fn transpose_square_1<T>(matrix: &mut [T], size: usize) {
    debug_assert_eq!(matrix.len(), size * size);
    if size % 2 != 0 {
        unimplemented!("odd sizes are not supported");
    }

    // iterate over upper-left triangle, working in 2x2 blocks
    for row in (0..size).step_by(2) {
        let i = row * size + row;
        matrix.swap(i + 1, i + size);
        for col in (row..size).step_by(2).skip(1) {
            let i = row * size + col;
            let j = col * size + row;
            matrix.swap(i, j);
            matrix.swap(i + 1, j + size);
            matrix.swap(i + size, j + 1);
            matrix.swap(i + size + 1, j + size + 1);
        }
    }
}

fn transpose_square_2<T>(matrix: &mut [T], size: usize) {
    debug_assert_eq!(matrix.len(), 2 * size * size);

    // iterate over upper-left triangle, working in 1x2 blocks
    for row in 0..size {
        for col in (row..size).skip(1) {
            let i = (row * size + col) * 2;
            let j = (col * size + row) * 2;
            matrix.swap(i, j);
            matrix.swap(i + 1, j + 1);
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn clone_and_shift<E: FieldElement>(source: &[E], destination: &mut [E], offset: E::BaseField) {
    let batch_size = source.len() / rayon::current_num_threads().next_power_of_two();
    source
        .par_chunks(batch_size)
        .zip(destination.par_chunks_mut(batch_size))
        .enumerate()
        .for_each(|(i, (source, destination))| {
            let mut factor = offset.exp(((i * batch_size) as u64).into());
            for (s, d) in source.iter().zip(destination.iter_mut()) {
                *d = (*s).mul_base(factor);
                factor = factor * offset;
            }
        });
}
