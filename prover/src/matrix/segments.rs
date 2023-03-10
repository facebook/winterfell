// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::{fft::fft_inputs::FftInputs, FieldElement};
use utils::collections::Vec;

// CONSTANTS
// ================================================================================================

pub const ARR_SIZE: usize = 8;

// SEGMENT OF ROW-MAJOR MATRIX
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
pub struct Segment<E: FieldElement> {
    data: Vec<[E; ARR_SIZE]>,
}

impl<E: FieldElement> Segment<E> {
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
        self.data.fft_in_place(twiddles);
        self.data.permute()
    }
}
