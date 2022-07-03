// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::super::permute_index;
use crate::{
    field::{FieldElement, StarkField},
    utils::log2,
    Matrix,
};

// CONSTANTS
// ================================================================================================
const MAX_LOOP: usize = 256;

/// Interpolates `evaluations` over a domain of length `evaluations.len()` in the field specified
/// `B` into a polynomial in coefficient form using the FFT algorithm.
pub fn interpolate_poly<B, E, M>(evaluations: &mut M, inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E>,
{
    fft_in_place(evaluations, inv_twiddles, 1, 1, 0);
    let inv_length = E::inv((evaluations.num_rows() as u64).into());
    for i in 0..evaluations.num_rows() {
        for j in 0..evaluations.num_cols() {
            evaluations.set(j, i, evaluations.get(j, i) * inv_length);
        }
    }
    permute(evaluations);
}

/// Evaluates polynomial `p` over the domain of length `p.len()` * `blowup_factor` shifted by
/// `domain_offset` in the field specified `B` using the FFT algorithm and returns the result.
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
    let domain_size = p.num_rows() * blowup_factor;
    let num_cols = p.num_cols();
    let g = B::get_root_of_unity(log2(domain_size));
    let mut result = M::uninit(domain_size, num_cols);

    result
        .data_mut()
        .chunks_mut(p.num_rows() * num_cols)
        .enumerate()
        .for_each(|(i, chunk)| {
            let mut mat = M::as_ref_table(chunk, num_cols);
            let idx = permute_index(blowup_factor, i) as u64;
            let offset = g.exp(idx.into()) * domain_offset;
            let mut factor = E::BaseField::ONE;
            for (d, c) in mat.rows_mut().zip(p.rows()) {
                for i in 0..num_cols {
                    d[i] = c[i].mul_base(factor);
                }
                factor *= offset;
            }
            fft_in_place(&mut mat, twiddles, 1, 1, 0);
        });

    permute(&mut result);
    result
}

// PERMUTATIONS
// ================================================================================================

pub fn permute<M: Matrix<E>, E: FieldElement>(values: &mut M) {
    let n = values.num_rows();
    for i in 0..n {
        let j = permute_index(n, i);
        if j > i {
            swap(values, i, j);
        }
    }
}

pub fn swap<M: Matrix<E>, E: FieldElement>(values: &mut M, i: usize, j: usize) {
    for col_idx in 0..values.num_cols() {
        let temp = values.get(col_idx, i);
        values.set(col_idx, i, values.get(col_idx, j));
        values.set(col_idx, j, temp);
    }
}

// CORE FFT ALGORITHM
// ================================================================================================

/// In-place recursive FFT with permuted output.
///
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
pub(super) fn fft_in_place<B, E, M>(
    values: &mut M,
    twiddles: &[B],
    count: usize,
    stride: usize,
    offset: usize,
) where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E>,
{
    let size = values.num_rows() / stride;
    debug_assert!(size.is_power_of_two());
    debug_assert!(offset < stride);
    debug_assert_eq!(values.num_rows() % size, 0);

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
fn butterfly<E, M>(values: &mut M, offset: usize, stride: usize)
where
    E: FieldElement,
    M: Matrix<E>,
{
    let i = offset;
    let j = offset + stride;

    for col_idx in 0..values.num_cols() {
        let temp = values.get(col_idx, i);
        values.set(col_idx, i, temp + values.get(col_idx, j));
        values.set(col_idx, j, temp - values.get(col_idx, j));
    }
}

#[inline(always)]
fn butterfly_twiddle<B, E, M>(values: &mut M, twiddle: B, offset: usize, stride: usize)
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E>,
{
    let i = offset;
    let j = offset + stride;

    for col_idx in 0..values.num_cols() {
        let temp = values.get(col_idx, i);
        values.set(col_idx, j, values.get(col_idx, j).mul_base(twiddle));
        values.set(col_idx, i, temp + values.get(col_idx, j));
        values.set(col_idx, j, temp - values.get(col_idx, j));
    }
}
