// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::super::permute_index;
use crate::{
    field::{FieldElement, StarkField},
    utils::log2,
    Matrix, RowMajorRefTable,
};
use std::marker::{Send, Sync};
use utils::{collections::Vec, iterators::*, rayon, uninit_vector};

/// Uses FFT algorithm to interpolate a polynomial from provided `values`; the interpolation
/// is done in-place, meaning `values` are updated with polynomial coefficients.
pub fn interpolate_poly<B, E, M>(v: &mut M, inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E> + Send + Sync,
{
    split_radix_fft(v, inv_twiddles);
    let inv_length = E::inv((v.num_rows() as u64).into());
    for i in 0..v.num_rows() {
        for j in 0..v.num_cols() {
            v.set(j, i, v.get(j, i) * inv_length);
        }
    }
    super::serial::permute(v);
}

/// Evaluates polynomial `p` using FFT algorithm and returns the result. The polynomial is
/// evaluated over domain specified by `twiddles`, expanded by the `blowup_factor`, and shifted
/// by the `domain_offset`.
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
    let num_cols = p.num_cols();
    let domain_size = p.num_rows() * blowup_factor;
    let g = B::get_root_of_unity(log2(domain_size));
    let mut result = unsafe { M::uninit(domain_size, num_cols) };

    result
        .data_mut()
        .par_chunks_mut(p.num_rows() * num_cols)
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = permute_index(blowup_factor, i) as u64;
            let offset = g.exp(idx.into()) * domain_offset;
            clone_and_shift(p, chunk, offset);
            let mut mat = M::as_ref_table(chunk, num_cols);
            split_radix_fft(&mut mat, twiddles);
        });

    super::serial::permute(&mut result);
    result
}

// PERMUTATIONS
// ================================================================================================

// TODO: Implement concurrent permutation for RowMajorMatrix
//pub fn permute<E: FieldElement, M: Matrix<E>>(v: &mut M) {
//    let n = v.len();
//    let num_batches = rayon::current_num_threads().next_power_of_two();
//    let batch_size = n / num_batches;
//    rayon::scope(|s| {
//        for batch_idx in 0..num_batches {
//            // create another mutable reference to the slice of values to use in a new thread; this
//            // is OK because we never write the same positions in the slice from different threads
//            let values = unsafe { &mut *(&mut v[..] as *mut [E]) };
//            s.spawn(move |_| {
//                let batch_start = batch_idx * batch_size;
//                let batch_end = batch_start + batch_size;
//                for i in batch_start..batch_end {
//                    let j = permute_index(n, i);
//                    if j > i {
//                        values.swap(i, j);
//                    }
//                }
//            });
//        }
//    });
//}

// SPLIT-RADIX FFT
// ================================================================================================

/// In-place recursive FFT with permuted output.
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
pub(super) fn split_radix_fft<B, E, M>(values: &mut M, twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    M: Matrix<E> + Send + Sync,
{
    // generator of the domain should be in the middle of twiddles
    let n = values.num_rows();
    let g = twiddles[twiddles.len() / 2];
    debug_assert_eq!(g.exp((n as u32).into()), E::BaseField::ONE);

    let inner_len = 1_usize << (log2(n) / 2);
    let outer_len = n / inner_len;
    let stretch = outer_len / inner_len;
    debug_assert!(outer_len == inner_len || outer_len == 2 * inner_len);
    debug_assert_eq!(outer_len * inner_len, n);

    // transpose inner x inner x stretch square matrix
    transpose_square_stretch(values, inner_len, stretch);

    let num_cols = values.num_cols();

    // apply inner FFTs
    values
        .data_mut()
        .par_chunks_mut(outer_len * num_cols)
        .for_each(|chunk| {
            let mut mat = M::as_ref_table(chunk, num_cols);
            super::serial::fft_in_place(&mut mat, &twiddles, stretch, stretch, 0)
        });

    // transpose inner x inner x stretch square matrix
    transpose_square_stretch(values, inner_len, stretch);

    // apply outer FFTs
    values
        .data_mut()
        .par_chunks_mut(outer_len * num_cols)
        .enumerate()
        .for_each(|(i, chunk)| {
            let mut mat = M::as_ref_table(chunk, num_cols);
            if i > 0 {
                let i = permute_index(inner_len, i);
                let inner_twiddle = g.exp((i as u32).into());
                let mut outer_twiddle = inner_twiddle;
                for row in mat.rows_mut().skip(1) {
                    for n in 0..num_cols {
                        row[n] = row[n].mul_base(outer_twiddle);
                    }
                    outer_twiddle = outer_twiddle * inner_twiddle;
                }
            }
            super::serial::fft_in_place(&mut mat, &twiddles, 1, 1, 0)
        });
}

// TRANSPOSING
// ================================================================================================

fn transpose_square_stretch<E: FieldElement, M: Matrix<E>>(
    matrix: &mut M,
    size: usize,
    stretch: usize,
) {
    assert_eq!(matrix.num_rows(), size * size * stretch);
    match stretch {
        1 => transpose_square_1(matrix, size),
        2 => transpose_square_2(matrix, size),
        _ => unimplemented!("only stretch sizes 1 and 2 are supported"),
    }
}

fn transpose_square_1<E: FieldElement, M: Matrix<E>>(matrix: &mut M, size: usize) {
    debug_assert_eq!(matrix.num_rows(), size * size);
    if size % 2 != 0 {
        unimplemented!("odd sizes are not supported");
    }

    // iterate over upper-left triangle, working in 2x2 blocks
    for row in (0..size).step_by(2) {
        let i = row * size + row;
        super::serial::swap(matrix, i + 1, i + size);
        for col in (row..size).step_by(2).skip(1) {
            let i = row * size + col;
            let j = col * size + row;
            super::serial::swap(matrix, i, j);
            super::serial::swap(matrix, i + 1, j + size);
            super::serial::swap(matrix, i + size, j + 1);
            super::serial::swap(matrix, i + size + 1, j + size + 1);
        }
    }
}

fn transpose_square_2<E: FieldElement, M: Matrix<E>>(matrix: &mut M, size: usize) {
    debug_assert_eq!(matrix.num_rows(), 2 * size * size);

    // iterate over upper-left triangle, working in 1x2 blocks
    for row in 0..size {
        for col in (row..size).skip(1) {
            let i = (row * size + col) * 2;
            let j = (col * size + row) * 2;
            super::serial::swap(matrix, i, j);
            super::serial::swap(matrix, i + 1, j + 1);
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn clone_and_shift<E: FieldElement, M: Matrix<E> + Send + Sync>(
    source: &M,
    destination_data: &mut [E],
    offset: E::BaseField,
) {
    let num_cols = source.num_cols();
    let batch_size = source.num_rows() / rayon::current_num_threads().next_power_of_two();
    source
        .data()
        .par_chunks(batch_size * num_cols)
        .zip(destination_data.par_chunks_mut(batch_size * num_cols))
        .enumerate()
        .for_each(|(i, (source_data, destination_data))| {
            let mut destination = M::as_ref_table(destination_data, num_cols);
            let mut factor = offset.exp(((i * batch_size) as u64).into());
            for (s, d) in source_data.chunks(num_cols).zip(destination.rows_mut()) {
                for i in 0..num_cols {
                    d[i] = s[i].mul_base(factor);
                }
                factor = factor * offset;
            }
        });
}
