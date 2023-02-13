// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::segments::{Segment, Segments};
use crate::{matrix::ARR_SIZE, Matrix};
use math::{fft, FieldElement, StarkField};
use utils::collections::Vec;
use utils::{flatten_vector_elements, uninit_vector};

// ROWMAJOR MATRIX
// ================================================================================================

/// A row-major matrix of field elements. The matrix is represented as a single vector of field
/// elements, where the first `row_len` elements represent the first row of the matrix, the next
/// `row_len` elements represent the second row, and so on.
///
/// # Note
/// - The number of rows in the matrix is always a multiple of the ARR_SIZE.
/// - The number of columns in the matrix is always a multiple of the ARR_SIZE.
#[derive(Clone, Debug)]
pub struct RowMatrix<E: FieldElement> {
    data: Vec<E>,
    row_len: usize,
}

impl<E> RowMatrix<E>
where
    E: FieldElement,
{
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new row-major matrix from the specified data and row length. The data must be
    /// arranged in row-major order, i.e. the first `row_len` elements of the data represent the first
    /// row of the matrix, the next `row_len` elements represent the second row, and so on.
    ///
    /// # Panics
    /// - if the number of elements in the data is not a multiple of the specified row length;
    /// - if the specified row length is not a multiple of the ARR_SIZE;
    /// - if the specified data is empty.
    pub fn new(data: Vec<E>, row_len: usize) -> Self {
        assert!(data.len() % row_len == 0);
        assert!(row_len % ARR_SIZE == 0);
        assert!(!data.is_empty());

        Self { data, row_len }
    }

    /// Converts a column-major matrix of polynomials `Matrix<E>` into a RowMatrix evaluated at
    /// a shifted domain offset.
    pub fn from_polys(polys: &Matrix<E>, blowup_factor: usize) -> Self {
        // get the number of rows and columns in the polys.
        let row_width = polys.num_cols();
        let num_rows = polys.num_rows();

        // get the twiddles for the segment.
        let twiddles = fft::get_twiddles::<E::BaseField>(polys.num_rows() * blowup_factor);
        let domain_offset = E::BaseField::GENERATOR;

        // get the number of segments in the matrix.
        let num_of_segments = row_width / ARR_SIZE;
        let mut segments = Segments::new(Vec::new());

        // precompute offsets for each row.
        let mut offsets = Vec::with_capacity(num_rows);
        offsets.push(E::BaseField::ONE);
        for i in 1..num_rows {
            offsets.push(offsets[i - 1] * domain_offset);
        }

        // create segments.
        (0..num_of_segments).for_each(|i| {
            // create a vector of arrays to hold the result.
            let mut result_vec_of_arrays =
                unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * blowup_factor) };

            // transpose the segment into `Segment` and evaluate the polynomials at the
            // shifted domain offset.
            (i * ARR_SIZE..(i + 1) * ARR_SIZE).for_each(|col_idx| {
                let row = polys.get_column(col_idx);
                row.iter().enumerate().for_each(|(row_idx, elem)| {
                    result_vec_of_arrays[row_idx][col_idx - i * ARR_SIZE] =
                        elem.mul_base(offsets[row_idx]);
                });
            });

            // create a `Segment` object from the result.
            let row_matrix = Segment::new(result_vec_of_arrays);
            segments.push(row_matrix);
        });

        // evaluate the polynomials in each segment at the shifted domain offset.
        for segment in segments.iter_mut() {
            segment.evaluate_poly(&twiddles);
        }

        let num_rows = num_rows * blowup_factor;

        // create a vector of arrays to hold the result.
        let mut result = unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * row_width / ARR_SIZE) };

        // transpose the segments into a row matrix.
        segments.iter().enumerate().for_each(|(i, segment)| {
            (segment.as_data()).iter().enumerate().for_each(|(j, row)| {
                result[j * row_width / ARR_SIZE + i] = *row;
            })
        });

        // create a `RowMatrix` object from the result.
        RowMatrix {
            data: flatten_vector_elements(result),
            row_len: row_width,
        }
    }

    // PUBLIC ACCESSORS
    // ---------------------------------------------------------------------------------------------

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.data.len() / self.row_len
    }

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        self.row_len
    }

    /// Returns a reference to a row at the specified index in this matrix.
    ///
    /// # Panics
    /// Panics if the specified row index is out of bounds.
    pub fn get_row(&self, row_idx: usize) -> &[E] {
        assert!(row_idx < self.num_rows());
        let start = row_idx * self.row_len;
        &self.data[start..start + self.row_len]
    }

    /// Returns a mutable reference to a row at the specified index in this matrix.
    ///
    /// # Panics
    /// Panics if the specified row index is out of bounds.
    pub fn get_row_mut(&mut self, row_idx: usize) -> &mut [E] {
        assert!(row_idx < self.num_rows());
        let start = row_idx * self.row_len;
        &mut self.data[start..start + self.row_len]
    }

    /// Returns the data in this matrix as a slice of field elements.
    pub fn as_data(&self) -> &[E] {
        &self.data
    }
}
