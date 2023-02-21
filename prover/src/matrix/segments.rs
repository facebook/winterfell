// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::{fft::fft_inputs::FftInputs, FieldElement};
use utils::collections::Vec;

// CONSTANTS
// ================================================================================================

pub const ARR_SIZE: usize = 8;

// SEGMENT OF ROWMAJOR MATRIX
// ================================================================================================

/// A segment of a row-major matrix of field elements. The segment is represented as a single vector
/// of field elements, where the first element represent the first row of the segment, the element at
/// index `i` represents the `i`-th row of the segment, and so on.
///
/// Each segment contains only `ARR_SIZE` columns of the matrix. For example, if we have the following
/// matrix with 8 columns and 2 rows (the matrix is represented as a single vector of field elements
/// in row-major order) and a ARR_SIZE of 2:
///
/// ```text
/// [ 1  2  3  4  5  6  7  8 ]
/// [ 9 10 11 12 13 14 15 16 ]
/// ```
/// then the first segment of this matrix is represented as a single vector of field elements:
/// ```text
/// [[1 2] [9 10]]
/// ```
/// and the second segment is represented as:
/// ```text
/// [[3 4] [11 12]]
/// ```
/// and so on.
///
/// It is arranged in a way that allows for efficient FFT operations.
#[derive(Clone, Debug)]
pub struct Segment<E>
where
    E: FieldElement,
{
    data: Vec<[E; ARR_SIZE]>,
}

impl<E> Segment<E>
where
    E: FieldElement,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new segment of a row-major matrix from the specified data.
    pub fn new(data: Vec<[E; ARR_SIZE]>) -> Self {
        Self { data }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.data.len()
    }

    /// Returns the data in this matrix as a slice of arrays.
    pub fn as_data(&self) -> &[[E; ARR_SIZE]] {
        &self.data
    }

    /// Returns the data in this matrix as a mutable slice of arrays.
    pub fn as_mut_data(&mut self) -> &mut [[E; ARR_SIZE]] {
        &mut self.data
    }

    /// Evaluates the segment `p` over the domain of length `p.len()` using the FFT algorithm
    /// and returns the result. The computation is performed in place.
    pub fn evaluate_poly(&mut self, twiddles: &[E::BaseField])
    where
        E: FieldElement,
    {
        self.fft_in_place(twiddles);
        self.permute()
    }
}

/// Implementation of `FftInputs` for `Segment`.
impl<E> FftInputs<E> for Segment<E>
where
    E: FieldElement,
{
    fn len(&self) -> usize {
        self.num_rows()
    }

    #[inline(always)]
    fn butterfly(&mut self, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;

        let temp = self.data[i];

        //  apply on 1st element of the array.
        self.data[i][0] = temp[0] + self.data[j][0];
        self.data[j][0] = temp[0] - self.data[j][0];

        // apply on 2nd element of the array.
        self.data[i][1] = temp[1] + self.data[j][1];
        self.data[j][1] = temp[1] - self.data[j][1];

        // apply on 3rd element of the array.
        self.data[i][2] = temp[2] + self.data[j][2];
        self.data[j][2] = temp[2] - self.data[j][2];

        // apply on 4th element of the array.
        self.data[i][3] = temp[3] + self.data[j][3];
        self.data[j][3] = temp[3] - self.data[j][3];

        // apply on 5th element of the array.
        self.data[i][4] = temp[4] + self.data[j][4];
        self.data[j][4] = temp[4] - self.data[j][4];

        // apply on 6th element of the array.
        self.data[i][5] = temp[5] + self.data[j][5];
        self.data[j][5] = temp[5] - self.data[j][5];

        // apply on 7th element of the array.
        self.data[i][6] = temp[6] + self.data[j][6];
        self.data[j][6] = temp[6] - self.data[j][6];

        // apply on 8th element of the array.
        self.data[i][7] = temp[7] + self.data[j][7];
        self.data[j][7] = temp[7] - self.data[j][7];
    }

    #[inline(always)]
    fn butterfly_twiddle(&mut self, twiddle: E::BaseField, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;

        let twiddle = E::from(twiddle);
        let temp = self.data[i];

        // apply of index 0 of twiddle.
        self.data[j][0] *= twiddle;
        self.data[i][0] = temp[0] + self.data[j][0];
        self.data[j][0] = temp[0] - self.data[j][0];

        // apply of index 1 of twiddle.
        self.data[j][1] *= twiddle;
        self.data[i][1] = temp[1] + self.data[j][1];
        self.data[j][1] = temp[1] - self.data[j][1];

        // apply of index 2 of twiddle.
        self.data[j][2] *= twiddle;
        self.data[i][2] = temp[2] + self.data[j][2];
        self.data[j][2] = temp[2] - self.data[j][2];

        // apply of index 3 of twiddle.
        self.data[j][3] *= twiddle;
        self.data[i][3] = temp[3] + self.data[j][3];
        self.data[j][3] = temp[3] - self.data[j][3];

        // apply of index 4 of twiddle.
        self.data[j][4] *= twiddle;
        self.data[i][4] = temp[4] + self.data[j][4];
        self.data[j][4] = temp[4] - self.data[j][4];

        // apply of index 5 of twiddle.
        self.data[j][5] *= twiddle;
        self.data[i][5] = temp[5] + self.data[j][5];
        self.data[j][5] = temp[5] - self.data[j][5];

        // apply of index 6 of twiddle.
        self.data[j][6] *= twiddle;
        self.data[i][6] = temp[6] + self.data[j][6];
        self.data[j][6] = temp[6] - self.data[j][6];

        // apply of index 7 of twiddle.
        self.data[j][7] *= twiddle;
        self.data[i][7] = temp[7] + self.data[j][7];
        self.data[j][7] = temp[7] - self.data[j][7];
    }

    fn swap(&mut self, i: usize, j: usize) {
        self.data.swap(i, j);
    }

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField) {
        let increment = E::from(increment);
        let mut offset = E::from(offset);

        for row_idx in 0..self.len() {
            self.data[row_idx][0] *= offset;
            self.data[row_idx][1] *= offset;
            self.data[row_idx][2] *= offset;
            self.data[row_idx][3] *= offset;
            self.data[row_idx][4] *= offset;
            self.data[row_idx][5] *= offset;
            self.data[row_idx][6] *= offset;
            self.data[row_idx][7] *= offset;

            offset *= increment;
        }
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);

        for row_idx in 0..self.len() {
            self.data[row_idx][0] *= offset;
            self.data[row_idx][1] *= offset;
            self.data[row_idx][2] *= offset;
            self.data[row_idx][3] *= offset;
            self.data[row_idx][4] *= offset;
            self.data[row_idx][5] *= offset;
            self.data[row_idx][6] *= offset;
            self.data[row_idx][7] *= offset;
        }
    }
}
