// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::log2;

use super::{permute_index, FieldElement};

// #[cfg(feature = "concurrent")]
use rayon::{
    self,
    prelude::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

// CONSTANTS
// ================================================================================================
const MAX_LOOP: usize = 256;

// FFTINPUTS TRAIT
// ================================================================================================

#[allow(clippy::len_without_is_empty)]
/// Defines the interface that must be implemented by the input to fft_in_place method.
pub trait FftInputs<E: FieldElement> {
    /// A chunk of this fftinputs.
    type ChunkItem<'b>: FftInputs<E>
    where
        Self: 'b,
        E: 'b;

    // #[cfg(feature = "concurrent")]
    /// A parallel iterator over mutable chunks of this fftinputs.
    type ParChunksMut<'c>: IndexedParallelIterator<Item = Self::ChunkItem<'c>>
    where
        Self: 'c,
        E: 'c;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of elements in this input.
    fn len(&self) -> usize;

    /// Combines the result of smaller number theoretic transform into a larger NTT.
    fn butterfly(&mut self, offset: usize, stride: usize);

    /// Combines the result of smaller number theoretic transform multiplied with a
    /// twiddle factor into a larger NTT.
    fn butterfly_twiddle(&mut self, twiddle: E::BaseField, offset: usize, stride: usize);

    /// Swaps the element at index i with the element at index j. Specifically:
    ///
    /// elem_i <-> elem_j
    ///
    /// # Panics
    /// Panics if i or j are out of bounds.
    fn swap(&mut self, i: usize, j: usize);

    /// Multiplies every element in this input by a series of increment. Specifically:
    ///
    /// elem_i = elem_i * offset * increment^i
    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField, num_skip: usize);

    /// Multiplies every element in this input by `offset`. Specifically:
    ///
    /// elem_i = elem_i * offset
    fn shift_by(&mut self, offset: E::BaseField);

    // #[cfg(feature = "concurrent")]
    /// Returns a slice of elements in this input concurrently. The returned slice is
    /// guaranteed to be a subset of the elements in this input.
    fn par_mut_chunks(&mut self, chunk_size: usize) -> Self::ParChunksMut<'_>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Permutes the elements in this input using the permutation defined by the given
    /// permutation index.
    ///
    /// The permutation index is a number between 0 and `self.len() - 1` that specifies the
    /// permutation to apply to the input. The permutation is applied in place, so the input
    /// is replaced with the result of the permutation. The permutation is applied by swapping
    /// elements in the input.
    ///
    /// # Panics
    /// Panics if the permutation index is out of bounds.
    fn permute(&mut self) {
        let n = self.len();
        for i in 0..n {
            let j = permute_index(n, i);
            if j > i {
                self.swap(i, j);
            }
        }
    }

    /// Applies the FFT to this input.
    ///
    /// The FFT is applied in place, so the input is replaced with the result of the FFT. The
    /// `twiddles` parameter specifies the twiddle factors to use for the FFT.
    ///
    /// # Panics
    /// Panics if length of the `twiddles` parameter is not self.len() / 2.
    fn fft_in_place(&mut self, twiddles: &[B]) {
        fft_in_place(self, twiddles, 1, 1, 0);
    }

    // CONCURRENT METHODS
    // --------------------------------------------------------------------------------------------

    // PERMUTATIONS
    // ================================================================================================

    // #[cfg(feature = "concurrent")]
    /// Permutes the elements in this input using the permutation defined by the given
    /// permutation index in a concurrent manner.
    fn permute_concurrent(&mut self)
    where
        Self: Send,
    {
        let n = self.len();
        let num_batches = rayon::current_num_threads().next_power_of_two();
        let batch_size = n / num_batches.min(n);
        rayon::scope(|s| {
            for batch_idx in 0..num_batches {
                // create another mutable reference to the slice of values to use in a new thread; this
                // is OK because we never write the same positions in the slice from different threads
                let values = unsafe { &mut *(&mut *self as *mut Self) };
                s.spawn(move |_| {
                    let batch_start = batch_idx * batch_size;
                    let batch_end = batch_start + batch_size;
                    for i in batch_start..batch_end {
                        let j = permute_index(n, i);
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

    // #[cfg(feature = "concurrent")]
    /// In-place recursive FFT with permuted output.
    /// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
    fn split_radix_fft(&mut self, twiddles: &[E::BaseField]) {
        // generator of the domain should be in the middle of twiddles
        let n = self.len();
        let g = twiddles[twiddles.len() / 2];
        debug_assert_eq!(g.exp((n as u32).into()), E::BaseField::ONE);

        let inner_len = 1_usize << (log2(n) / 2);
        let outer_len = n / inner_len;
        let stretch = outer_len / inner_len;
        debug_assert!(outer_len == inner_len || outer_len == 2 * inner_len);
        debug_assert_eq!(outer_len * inner_len, n);

        // transpose inner x inner x stretch square matrix
        transpose_square_stretch(self, inner_len, stretch);

        // apply inner FFTs
        self.par_mut_chunks(outer_len)
            .for_each(|mut row| fft_in_place(&mut row, twiddles, stretch, stretch, 0));

        // transpose inner x inner x stretch square matrix
        transpose_square_stretch(self, inner_len, stretch);

        // apply outer FFTs
        self.par_mut_chunks(outer_len)
            .enumerate()
            .for_each(|(i, mut row)| {
                if i > 0 {
                    let i = permute_index(inner_len, i);
                    let inner_twiddle = g.exp((i as u32).into());
                    let outer_twiddle = inner_twiddle;
                    row.shift_by_series(outer_twiddle, inner_twiddle, 1);
                }
                row.fft_in_place(twiddles)
            });
    }
}

/// Implements FftInputs for a slice of field elements.
impl<E> FftInputs<E> for [E]
where
    E: FieldElement,
{
    type ChunkItem<'b> = &'b mut [E] where E: 'b;
    type ParChunksMut<'c> = rayon::slice::ChunksMut<'c, E> where Self: 'c;

    fn len(&self) -> usize {
        self.len()
    }

    #[inline(always)]
    fn butterfly(&mut self, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;
        let temp = self[i];
        self[i] = temp + self[j];
        self[j] = temp - self[j];
    }

    #[inline(always)]
    fn butterfly_twiddle(&mut self, twiddle: E::BaseField, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;
        let temp = self[i];
        self[j] = self[j].mul_base(twiddle);
        self[i] = temp + self[j];
        self[j] = temp - self[j];
    }

    fn swap(&mut self, i: usize, j: usize) {
        self.swap(i, j)
    }

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField, num_skip: usize) {
        let mut offset = E::from(offset);
        let increment = E::from(increment);
        for d in self.iter_mut().skip(num_skip) {
            *d *= offset;
            offset *= increment;
        }
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);
        for d in self.iter_mut() {
            *d *= offset;
        }
    }

    // #[cfg(feature = "concurrent")]
    fn par_mut_chunks(&mut self, size: usize) -> Self::ParChunksMut<'_> {
        self.par_chunks_mut(size)
    }
}

/// Implements FftInputs for a slice of field elements.
impl<'a, E> FftInputs<E> for &'a mut [E]
where
    E: FieldElement,
{
    type ChunkItem<'b> = &'b mut [E] where Self: 'b, E: 'b;
    type ParChunksMut<'c> = rayon::slice::ChunksMut<'c, E> where Self: 'c;

    fn len(&self) -> usize {
        <[E] as FftInputs<E>>::len(self)
    }

    #[inline(always)]
    fn butterfly(&mut self, offset: usize, stride: usize) {
        <[E] as FftInputs<E>>::butterfly(self, offset, stride)
    }

    #[inline(always)]
    fn butterfly_twiddle(&mut self, twiddle: E::BaseField, offset: usize, stride: usize) {
        <[E] as FftInputs<E>>::butterfly_twiddle(self, twiddle, offset, stride)
    }

    fn swap(&mut self, i: usize, j: usize) {
        <[E] as FftInputs<E>>::swap(self, i, j)
    }

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField, num_skip: usize) {
        <[E] as FftInputs<E>>::shift_by_series(self, offset, increment, num_skip)
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        <[E] as FftInputs<E>>::shift_by(self, offset)
    }

    // #[cfg(feature = "concurrent")]
    fn par_mut_chunks(&mut self, size: usize) -> Self::ParChunksMut<'_> {
        <[E] as FftInputs<E>>::par_mut_chunks(self, size)
    }
}

// CORE FFT ALGORITHM
// ================================================================================================

/// In-place recursive FFT with permuted output.
///
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
pub(super) fn fft_in_place<E, I>(
    values: &mut I,
    twiddles: &[E::BaseField],
    count: usize,
    stride: usize,
    offset: usize,
) where
    E: FieldElement,
    I: FftInputs<E> + ?Sized,
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

    // Apply butterfly operations.
    for offset in offset..(offset + count) {
        I::butterfly(values, offset, stride);
    }

    // Apply butterfly operations with twiddle factors.
    let last_offset = offset + size * stride;
    for (i, offset) in (offset..last_offset)
        .step_by(2 * stride)
        .enumerate()
        .skip(1)
    {
        for j in offset..(offset + count) {
            I::butterfly_twiddle(values, twiddles[i], j, stride);
        }
    }
}

// TRANSPOSING
// ================================================================================================

// #[cfg(feature = "conc/urrent")]
fn transpose_square_stretch<E, I>(matrix: &mut I, size: usize, stretch: usize)
where
    E: FieldElement,
    I: FftInputs<E> + ?Sized,
{
    assert_eq!(matrix.len(), size * size * stretch);
    match stretch {
        1 => transpose_square_1(matrix, size),
        2 => transpose_square_2(matrix, size),
        _ => unimplemented!("only stretch sizes 1 and 2 are supported"),
    }
}

// #[cfg(feature = "concurrent")]
fn transpose_square_1<E, I>(matrix: &mut I, size: usize)
where
    E: FieldElement,
    I: FftInputs<E> + ?Sized,
{
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

// #[cfg(feature = "concurrent")]
fn transpose_square_2<E, I>(matrix: &mut I, size: usize)
where
    E: FieldElement,
    I: FftInputs<E> + ?Sized,
{
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
