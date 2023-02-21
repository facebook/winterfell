// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::segments::Segment;
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
/// - The number of rows in the matrix is always a multiple of ARR_SIZE.
/// - The number of columns in the matrix is always a multiple of ARR_SIZE.
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
    /// - if the specified row length is not a multiple of ARR_SIZE;
    /// - if the specified data is empty.
    pub fn new(data: Vec<E>, row_len: usize) -> Self {
        assert!(data.len() % row_len == 0);
        assert!(row_len % ARR_SIZE == 0);
        assert!(!data.is_empty());

        Self { data, row_len }
    }

    /// Converts a column-major matrix of polynomials `Matrix<E>` into a RowMatrix evaluated at
    /// a shifted domain offset.
    pub fn transpose_and_extend(polys: &Matrix<E>, blowup_factor: usize) -> Self {
        // get the number of rows and columns in the polys.
        let row_width = polys.num_cols();
        let num_rows = polys.num_rows();

        // get the twiddles for the segment.
        let twiddles = fft::get_twiddles::<E::BaseField>(polys.num_rows() * blowup_factor);

        // precompute offsets for each row.
        let offsets = get_offsets::<E>(num_rows, E::BaseField::GENERATOR);

        // create a vector of uninitialised segments to hold the result.
        let mut segments = allocate_segments::<E>(num_rows, row_width, blowup_factor);

        // create segments.
        segments
            .iter_mut()
            .enumerate()
            .for_each(|(seg_idx, segment)| {
                // prepare the segment.
                prepare_segment(segment, polys, seg_idx, &offsets);

                // evaluate the segment at the shifted domain offset.
                segment.evaluate_poly(&twiddles);
            });

        // create a `RowMatrix` object from the segments.
        Self::from_segments(segments)
    }

    /// Converts a collection of segments into a row-major matrix.
    fn from_segments(segments: Vec<Segment<E>>) -> Self {
        // get the number of rows and segments.
        let num_rows = segments[0].num_rows();
        let num_segs = segments.len();

        // create a vector of arrays to hold the result.
        // TODO: use a more efficient way so that we don't have to allocate a vector of arrays here.
        let mut result = unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * num_segs) };

        // transpose the segments into a row matrix.
        segments.iter().enumerate().for_each(|(i, segment)| {
            (segment.as_data()).iter().enumerate().for_each(|(j, row)| {
                result[j * num_segs + i] = *row;
            })
        });

        // create a `RowMatrix` object from the result.
        RowMatrix {
            data: flatten_vector_elements(result),
            row_len: num_segs * ARR_SIZE,
        }
    }

    // PUBLIC ACCESSORS
    // ---------------------------------------------------------------------------------------------

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.data.len() / self.row_len
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

    /// Returns the data in this matrix as a slice of field elements.
    pub fn as_data(&self) -> &[E] {
        &self.data
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a vector of offsets for the specified number of rows. The offsets are computed as
/// `domain_offset^i` for `i` in `[0, num_rows)`. The first offset is always 1.
fn get_offsets<E>(num_rows: usize, domain_offset: E::BaseField) -> Vec<E::BaseField>
where
    E: FieldElement,
{
    // create a vector to hold the offsets.
    let mut offsets = Vec::with_capacity(num_rows);

    // the first offset is always 1.
    offsets.push(E::BaseField::ONE);

    // compute the remaining offsets.
    for i in 1..num_rows {
        offsets.push(offsets[i - 1] * domain_offset);
    }

    offsets
}

/// Creates a vector of uninitialised segments to hold the result. The number of segments is
/// equal to the number of columns in the matrix divided by the ARR_SIZE. Each segment is
/// initialised with a vector of uninitialised arrays of length `num_rows * blowup_factor`.
///
/// # Panics
/// Panics if the number of columns in the matrix is not a multiple of ARR_SIZE.
fn allocate_segments<E>(num_rows: usize, row_width: usize, blowup_factor: usize) -> Vec<Segment<E>>
where
    E: FieldElement,
{
    assert!(
        row_width % ARR_SIZE == 0,
        "number of columns must be a multiple of ARR_SIZE"
    );
    let outer_vec_len = row_width / ARR_SIZE;

    // create a vector of uninitialised segments to hold the result.
    // SAFETY: we are creating a vector of uninitialised segments, and each segment is
    // initialised with a vector of uninitialised arrays of length `num_rows * blowup_factor`.
    // This is safe because we are not reading from the vectors, and we will initialise
    // the vectors before reading from them.
    let outer_vec: Vec<Segment<E>> = (0..outer_vec_len)
        .map(|_| Segment::new(unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * blowup_factor) }))
        .collect();

    outer_vec
}

/// Prepares a segment for evaluation by multiplying each element in the segment by the
/// corresponding offset.
fn prepare_segment<E>(
    segment: &mut Segment<E>,
    polys: &Matrix<E>,
    seg_idx: usize,
    offsets: &[E::BaseField],
) where
    E: FieldElement,
{
    (seg_idx * ARR_SIZE..(seg_idx + 1) * ARR_SIZE).for_each(|col_idx| {
        // get the column from the polys matrix.
        let col = polys.get_column(col_idx);
        col.iter().enumerate().for_each(|(row_idx, elem)| {
            segment.as_mut_data()[row_idx][col_idx - seg_idx * ARR_SIZE] =
                elem.mul_base(offsets[row_idx]);
        });
    });
}
