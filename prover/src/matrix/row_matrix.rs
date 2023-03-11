// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Matrix, Segment, SEGMENT_WIDTH};
use math::{fft, log2, FieldElement, StarkField};
use utils::collections::Vec;
use utils::{flatten_vector_elements, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// ROW-MAJOR MATRIX
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
        assert!(row_len % SEGMENT_WIDTH == 0);
        assert!(!data.is_empty());

        Self { data, row_len }
    }

    /// Converts a column-major matrix of polynomials `Matrix<E>` into a RowMatrix evaluated at
    /// a shifted domain offset.
    pub fn transpose_and_extend(polys: &Matrix<E>, blowup_factor: usize) -> Self {
        let poly_size = polys.num_rows();
        let num_segments = polys.num_cols() / SEGMENT_WIDTH;

        // compute twiddles for polynomial evaluation
        let twiddles = fft::get_twiddles::<E::BaseField>(polys.num_rows());

        // pre-compute offsets for each row
        let offsets = get_offsets::<E>(poly_size, blowup_factor, E::BaseField::GENERATOR);

        // build matrix segments by evaluating all polynomials
        let segments = (0..num_segments)
            .map(|i| Segment::new(polys, i * SEGMENT_WIDTH, &offsets, &twiddles))
            .collect::<Vec<_>>();

        // transpose data in individual segments into a single row-major matrix
        Self::from_segments(segments)
    }

    /// Converts a collection of segments into a row-major matrix.
    pub fn from_segments(segments: Vec<Segment<E>>) -> Self {
        // compute the size of each row
        let row_len = segments.len() * SEGMENT_WIDTH;

        // transpose the segments into a single vector of arrays
        let result = transpose(segments);

        // flatten the result to be a simple vector of elements and return
        RowMatrix {
            data: flatten_vector_elements(result),
            row_len,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

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

/// Returns a vector of offsets for an evaluation defined by the specified polynomial size, blowup
/// factor and domain offset.
///
/// When `concurrent` feature is enabled, offsets are computed in multiple threads.
fn get_offsets<E: FieldElement>(
    poly_size: usize,
    blowup_factor: usize,
    domain_offset: E::BaseField,
) -> Vec<E::BaseField> {
    let domain_size = poly_size * blowup_factor;
    let g = E::BaseField::get_root_of_unity(log2(domain_size));

    // allocate memory to hold the offsets
    let mut offsets = unsafe { uninit_vector(domain_size) };

    // define a closure to compute offsets for a given chunk of the result; the number of chunks
    // is defined by the blowup factor. for example, for blowup factor = 2, the number of chunks
    // will be 2, for blowup factor = 8, the number of chunks will be 8 etc.
    let compute_offsets = |(chunk_idx, chunk): (usize, &mut [E::BaseField])| {
        let idx = fft::permute_index(blowup_factor, chunk_idx) as u64;
        let offset = g.exp_vartime(idx.into()) * domain_offset;
        let mut factor = E::BaseField::ONE;
        for res in chunk.iter_mut() {
            *res = factor;
            factor *= offset;
        }
    };

    // compute offsets for each chunk using either parallel or regular iterators

    #[cfg(not(feature = "concurrent"))]
    offsets
        .chunks_mut(poly_size)
        .enumerate()
        .for_each(compute_offsets);

    #[cfg(feature = "concurrent")]
    offsets
        .par_chunks_mut(poly_size)
        .enumerate()
        .for_each(compute_offsets);

    offsets
}

/// Transposes a vector of segments into a single vector of fixed-size arrays.
///
/// When `concurrent` feature is enabled, transposition is performed in multiple threads.
fn transpose<E: FieldElement>(segments: Vec<Segment<E>>) -> Vec<[E; SEGMENT_WIDTH]> {
    let num_rows = segments[0].num_rows();
    let num_segs = segments.len();
    let result_len = num_rows * num_segs;

    // allocate memory to hold the transposed result;
    // TODO: investigate transposing in-place
    let mut result = unsafe { uninit_vector::<[E; SEGMENT_WIDTH]>(result_len) };

    // determine number of batches in which transposition will be preformed; if `concurrent`
    // feature is not enabled, the number of batches will always be 1
    let num_batches = get_num_batches(result_len);
    let rows_per_batch = num_rows / num_batches;

    // define a closure for transposing a given batch
    let transpose_batch = |(batch_idx, batch): (usize, &mut [[E; SEGMENT_WIDTH]])| {
        let row_offset = batch_idx * rows_per_batch;
        for i in 0..rows_per_batch {
            let row_idx = i + row_offset;
            for j in 0..num_segs {
                let v = &segments[j].data()[row_idx];
                batch[i * num_segs + j].copy_from_slice(v);
            }
        }
    };

    // call the closure either once (for single-threaded transposition) or in a parallel
    // iterator (for multi-threaded transposition)

    #[cfg(not(feature = "concurrent"))]
    transpose_batch((0, &mut result));

    #[cfg(feature = "concurrent")]
    result
        .par_chunks_mut(result_len / num_batches)
        .enumerate()
        .for_each(transpose_batch);

    result
}

#[cfg(not(feature = "concurrent"))]
fn get_num_batches(_input_size: usize) -> usize {
    1
}

#[cfg(feature = "concurrent")]
fn get_num_batches(input_size: usize) -> usize {
    if input_size < 1024 {
        return 1;
    }

    use utils::rayon;
    rayon::current_num_threads().next_power_of_two() * 2
}
