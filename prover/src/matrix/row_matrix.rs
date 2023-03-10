// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::segments::Segment;
use crate::{matrix::ARR_SIZE, Matrix};
use math::{fft, log2, FieldElement, StarkField};
use utils::collections::Vec;
use utils::{flatten_vector_elements, uninit_vector};

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
        assert!(row_len % ARR_SIZE == 0);
        assert!(!data.is_empty());

        Self { data, row_len }
    }

    /// Converts a column-major matrix of polynomials `Matrix<E>` into a RowMatrix evaluated at
    /// a shifted domain offset.
    pub fn transpose_and_extend(polys: &Matrix<E>, blowup_factor: usize) -> Self {
        let poly_size = polys.num_rows();
        let num_segments = polys.num_cols() / ARR_SIZE;

        // compute twiddles for polynomial evaluation
        let twiddles = fft::get_twiddles::<E::BaseField>(polys.num_rows());

        // pre-compute offsets for each row
        let offsets = get_offsets::<E>(poly_size, blowup_factor, E::BaseField::GENERATOR);

        // build matrix segments by evaluating all polynomials
        let segments = (0..num_segments)
            .map(|i| Segment::new(polys, i * ARR_SIZE, &offsets, &twiddles))
            .collect::<Vec<_>>();

        // transpose data in individual segments into a single row-major matrix
        Self::from_segments(segments)
    }

    /// Converts a collection of segments into a row-major matrix.
    pub fn from_segments(segments: Vec<Segment<E>>) -> Self {
        // get the number of rows and segments.
        let num_rows = segments[0].num_rows();
        let num_segs = segments.len();

        // create a vector of arrays to hold the result.
        // TODO: use a more efficient way so that we don't have to allocate a vector of arrays here.
        let mut result = unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * num_segs) };

        // transpose the segments into a row matrix.
        for i in 0..num_rows {
            for j in 0..num_segs {
                let v = &segments[j].as_data()[i];
                result[i * num_segs + j].copy_from_slice(v);
            }
        }

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

/// Returns a vector of offsets for an evaluation defined by the specified polynomial size, blowup
/// factor and domain offset.
fn get_offsets<E: FieldElement>(
    poly_size: usize,
    blowup_factor: usize,
    domain_offset: E::BaseField,
) -> Vec<E::BaseField> {
    let domain_size = poly_size * blowup_factor;

    let g = E::BaseField::get_root_of_unity(log2(domain_size));

    // create a vector to hold the offsets.
    let mut offsets = unsafe { uninit_vector(domain_size) };

    offsets
        .chunks_mut(poly_size)
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = permute_index(blowup_factor, i) as u64;
            let offset = g.exp_vartime(idx.into()) * domain_offset;
            let mut factor = E::BaseField::ONE;
            for res in chunk.iter_mut() {
                *res = factor;
                factor *= offset;
            }
        });

    offsets
}

fn permute_index(size: usize, index: usize) -> usize {
    const USIZE_BITS: usize = 0_usize.count_zeros() as usize;

    debug_assert!(index < size);
    if size == 1 {
        return 0;
    }
    debug_assert!(size.is_power_of_two());
    let bits = size.trailing_zeros() as usize;
    index.reverse_bits() >> (USIZE_BITS - bits)
}
