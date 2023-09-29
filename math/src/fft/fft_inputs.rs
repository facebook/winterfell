// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{permute_index, FieldElement};

// CONSTANTS
// ================================================================================================
const MAX_LOOP: usize = 256;

// FFT INPUTS TRAIT
// ================================================================================================

/// Defines the interface that must be implemented by the input to fft_in_place method.
#[allow(clippy::len_without_is_empty)]
pub trait FftInputs<E: FieldElement> {
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
    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField);

    /// Multiplies every element in this input by `offset`. Specifically:
    ///
    /// elem_i = elem_i * offset
    fn shift_by(&mut self, offset: E::BaseField);

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
    /// This is a convenience method equivalent to calling fft_in_place_raw(twiddles, 1, 1, 0).
    ///
    /// # Panics
    /// Panics if length of the `twiddles` parameter is not self.len() / 2.
    fn fft_in_place(&mut self, twiddles: &[E::BaseField]) {
        fft_in_place(self, twiddles, 1, 1, 0);
    }

    /// Applies the FFT to this input.
    ///
    /// The FFT is applied in place, so the input is replaced with the result of the FFT. The
    /// `twiddles` parameter specifies the twiddle factors to use for the FFT.
    ///
    /// # Panics
    /// Panics if length of the `twiddles` parameter is not self.len() / 2.
    fn fft_in_place_raw(
        &mut self,
        twiddles: &[E::BaseField],
        count: usize,
        stride: usize,
        offset: usize,
    ) {
        fft_in_place(self, twiddles, count, stride, offset)
    }
}

// SLICE IMPLEMENTATION
// ================================================================================================

/// Implements FftInputs for a slice of field elements.
impl<E: FieldElement> FftInputs<E> for [E] {
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

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField) {
        let mut offset = E::from(offset);
        let increment = E::from(increment);
        for d in self.iter_mut() {
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
}

// SLICE OF ARRAYS IMPLEMENTATION
// ================================================================================================

/// Implements [FftInputs] for a slice of field element arrays.
#[allow(clippy::needless_range_loop)]
impl<E: FieldElement, const N: usize> FftInputs<E> for [[E; N]] {
    fn len(&self) -> usize {
        self.len()
    }

    #[inline(always)]
    fn butterfly(&mut self, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;

        let temp = self[i];
        for col_idx in 0..N {
            self[i][col_idx] = temp[col_idx] + self[j][col_idx];
            self[j][col_idx] = temp[col_idx] - self[j][col_idx];
        }
    }

    #[inline(always)]
    fn butterfly_twiddle(&mut self, twiddle: E::BaseField, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;

        let twiddle = E::from(twiddle);
        let temp = self[i];

        for col_idx in 0..N {
            self[j][col_idx] *= twiddle;
            self[i][col_idx] = temp[col_idx] + self[j][col_idx];
            self[j][col_idx] = temp[col_idx] - self[j][col_idx];
        }
    }

    fn swap(&mut self, i: usize, j: usize) {
        self.swap(i, j)
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);
        for row_idx in 0..self.len() {
            for col_idx in 0..N {
                self[row_idx][col_idx] *= offset;
            }
        }
    }

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField) {
        let increment = E::from(increment);
        let mut offset = E::from(offset);

        for row_idx in 0..self.len() {
            for col_idx in 0..N {
                self[row_idx][col_idx] *= offset;
            }
            offset *= increment;
        }
    }
}

// CORE FFT ALGORITHM
// ================================================================================================

/// In-place recursive FFT with permuted output.
///
/// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
fn fft_in_place<E, I>(
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
    for (i, offset) in (offset..last_offset).step_by(2 * stride).enumerate().skip(1) {
        for j in offset..(offset + count) {
            I::butterfly_twiddle(values, twiddles[i], j, stride);
        }
    }
}
