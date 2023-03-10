// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Matrix;
use math::{fft::fft_inputs::FftInputs, FieldElement};
use utils::{collections::Vec, uninit_vector};

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
    /// Instantiates a new [Segment] by evaluating polynomials from the provided matrix starting
    /// at the specified offset.
    ///
    /// Evaluation is performed over the domain specified by the provided twiddles and offsets.
    ///
    /// # Panics
    /// Panics if:
    /// - Number of offsets is not a power of two.
    /// - Number of offsets is smaller than or equal to the polynomial size.
    /// - The number of twiddles is not half the size of the polynomial size.
    pub fn new(
        polys: &Matrix<E>,
        poly_offset: usize,
        offsets: &[E::BaseField],
        twiddles: &[E::BaseField],
    ) -> Self {
        let poly_size = polys.num_rows();
        let domain_size = offsets.len();

        debug_assert!(domain_size.is_power_of_two());
        debug_assert!(domain_size > poly_size);
        debug_assert_eq!(poly_size, twiddles.len() * 2);

        // allocate uninitialized memory for the segment
        let mut data = unsafe { uninit_vector::<[E; ARR_SIZE]>(domain_size) };

        // prepare the segment for FFT algorithm; this involves copying the polynomial coefficients
        // into the segment and applying the specified offsets.
        for i in 0..ARR_SIZE {
            let p = polys.get_column(poly_offset + i);
            data.chunks_mut(poly_size)
                .zip(offsets.chunks(poly_size))
                .for_each(|(d_chunk, o_chunk)| {
                    for row_idx in 0..poly_size {
                        d_chunk[row_idx][i] = p[row_idx].mul_base(o_chunk[row_idx])
                    }
                });
        }

        // run FFT algorithm and then permute the result
        data.chunks_mut(poly_size).for_each(|chunk| {
            chunk.fft_in_place(twiddles);
        });
        data.permute();

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
}
