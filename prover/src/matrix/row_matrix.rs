// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::PartitionOptions;
use crypto::{ElementHasher, VectorCommitment};
use math::{fft, FieldElement, StarkField};
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{batch_iter_mut, flatten_vector_elements, uninit_vector};

use super::{ColMatrix, Segment};
use crate::StarkDomain;

// ROW-MAJOR MATRIX
// ================================================================================================

/// A two-dimensional matrix of field elements arranged in row-major order.
///
/// The matrix is represented as a single vector of base field elements for the field defined by E
/// type parameter. The first `row_width` base field elements represent the first row of the matrix,
/// the next `row_width` base field elements represent the second row, and so on.
///
/// When rows are returned via the [RowMatrix::row()] method, base field elements are grouped
/// together as appropriate to form elements in E.
///
/// In some cases, rows may be padded with extra elements. The number of elements which are
/// accessible via the [RowMatrix::row()] method is specified by the `elements_per_row` member.
#[derive(Clone, Debug)]
pub struct RowMatrix<E: FieldElement> {
    /// Field elements stored in the matrix.
    data: Vec<E::BaseField>,
    /// Total number of base field elements stored in a single row.
    row_width: usize,
    /// Number of field elements in a single row accessible via the [RowMatrix::row()] method. This
    /// must be equal to or smaller than `row_width`.
    elements_per_row: usize,
}

impl<E: FieldElement> RowMatrix<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [RowMatrix] constructed by evaluating the provided polynomials over the
    /// domain defined by the specified blowup factor.
    ///
    /// The provided `polys` matrix is assumed to contain polynomials in coefficient form (one
    /// polynomial per column). Columns in the returned matrix will contain evaluations of the
    /// corresponding polynomials over the domain defined by polynomial size (i.e., number of rows
    /// in the `polys` matrix) and the `blowup_factor`.
    ///
    /// To improve performance, polynomials are evaluated in batches specified by the `N` type
    /// parameter. Minimum batch size is 1.
    pub fn evaluate_polys<const N: usize>(polys: &ColMatrix<E>, blowup_factor: usize) -> Self {
        assert!(N > 0, "batch size N must be greater than zero");

        // pre-compute offsets for each row
        let poly_size = polys.num_rows();
        let offsets =
            get_evaluation_offsets::<E>(poly_size, blowup_factor, E::BaseField::GENERATOR);

        // compute twiddles for polynomial evaluation
        let twiddles = fft::get_twiddles::<E::BaseField>(polys.num_rows());

        // build matrix segments by evaluating all polynomials
        let segments = build_segments::<E, N>(polys, &twiddles, &offsets);

        // transpose data in individual segments into a single row-major matrix
        Self::from_segments(segments, polys.num_base_cols())
    }

    /// Returns a new [RowMatrix] constructed by evaluating the provided polynomials over the
    /// specified [StarkDomain].
    ///
    /// The provided `polys` matrix is assumed to contain polynomials in coefficient form (one
    /// polynomial per column). Columns in the returned matrix will contain evaluations of the
    /// corresponding polynomials over the LDE domain defined by the provided [StarkDomain].
    ///
    /// To improve performance, polynomials are evaluated in batches specified by the `N` type
    /// parameter. Minimum batch size is 1.
    pub fn evaluate_polys_over<const N: usize>(
        polys: &ColMatrix<E>,
        domain: &StarkDomain<E::BaseField>,
    ) -> Self {
        assert!(N > 0, "batch size N must be greater than zero");

        // pre-compute offsets for each row
        let poly_size = polys.num_rows();
        let offsets =
            get_evaluation_offsets::<E>(poly_size, domain.trace_to_lde_blowup(), domain.offset());

        // build matrix segments by evaluating all polynomials
        let segments = build_segments::<E, N>(polys, domain.trace_twiddles(), &offsets);

        // transpose data in individual segments into a single row-major matrix
        Self::from_segments(segments, polys.num_base_cols())
    }

    /// Returns a new [RowMatrix] instantiated from the specified matrix segments.
    ///
    /// `elements_per_row` specifies how many base field elements are considered to form a single
    /// row in the matrix.
    ///
    /// # Panics
    /// Panics if
    /// - `segments` is an empty vector.
    /// - `elements_per_row` is greater than the row width implied by the number of segments and `N`
    ///   type parameter.
    pub fn from_segments<const N: usize>(
        segments: Vec<Segment<E::BaseField, N>>,
        elements_per_row: usize,
    ) -> Self {
        assert!(N > 0, "batch size N must be greater than zero");
        assert!(!segments.is_empty(), "a list of segments cannot be empty");

        // compute the size of each row
        let row_width = segments.len() * N;
        assert!(
            elements_per_row <= row_width,
            "elements per row cannot exceed {row_width}, but was {elements_per_row}"
        );

        // transpose the segments into a single vector of arrays
        let result = transpose(segments);

        // flatten the result to be a simple vector of elements and return
        RowMatrix {
            data: flatten_vector_elements(result),
            row_width,
            elements_per_row,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        self.elements_per_row / E::EXTENSION_DEGREE
    }

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.data.len() / self.row_width
    }

    /// Returns the element located at the specified column and row indexes in this matrix.
    ///
    /// # Panics
    /// Panics if either `col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn get(&self, col_idx: usize, row_idx: usize) -> E {
        self.row(row_idx)[col_idx]
    }

    /// Returns a reference to a row at the specified index in this matrix.
    ///
    /// # Panics
    /// Panics if the specified row index is out of bounds.
    pub fn row(&self, row_idx: usize) -> &[E] {
        assert!(row_idx < self.num_rows());
        let start = row_idx * self.row_width;
        E::slice_from_base_elements(&self.data[start..start + self.elements_per_row])
    }

    /// Returns the data in this matrix as a slice of field elements.
    pub fn data(&self) -> &[E::BaseField] {
        &self.data
    }

    // COMMITMENTS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to this matrix.
    ///
    /// The commitment is built as follows:
    /// * Each row of the matrix is hashed into a single digest of the specified hash function. The
    ///   result is a vector of digests of length equal to the number of matrix rows.
    /// * A vector commitment is computed for the resulting vector using the specified vector
    ///   commitment scheme.
    /// * The resulting vector commitment is returned as the commitment to the entire matrix.
    pub fn commit_to_rows<H, V>(&self, partition_options: PartitionOptions) -> V
    where
        H: ElementHasher<BaseField = E::BaseField>,
        V: VectorCommitment<H>,
    {
        // allocate vector to store row hashes
        let mut row_hashes = unsafe { uninit_vector::<H::Digest>(self.num_rows()) };
        let partition_size = partition_options.partition_size::<E>(self.num_cols());

        if partition_size == self.num_cols() {
            // iterate though matrix rows, hashing each row
            batch_iter_mut!(
                &mut row_hashes,
                128, // min batch size
                |batch: &mut [H::Digest], batch_offset: usize| {
                    for (i, row_hash) in batch.iter_mut().enumerate() {
                        *row_hash = H::hash_elements(self.row(batch_offset + i));
                    }
                }
            );
        } else {
            let num_partitions = partition_options.num_partitions::<E>(self.num_cols());

            // iterate though matrix rows, hashing each row
            batch_iter_mut!(
                &mut row_hashes,
                128, // min batch size
                |batch: &mut [H::Digest], batch_offset: usize| {
                    let mut buffer = vec![H::Digest::default(); num_partitions];
                    for (i, row_hash) in batch.iter_mut().enumerate() {
                        self.row(batch_offset + i)
                            .chunks(partition_size)
                            .zip(buffer.iter_mut())
                            .for_each(|(chunk, buf)| {
                                *buf = H::hash_elements(chunk);
                            });
                        *row_hash = H::merge_many(&buffer);
                    }
                }
            );
        }

        // build the vector commitment to the hashed rows
        V::new(row_hashes).expect("failed to construct trace vector commitment")
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a vector of offsets for an evaluation defined by the specified polynomial size, blowup
/// factor and domain offset.
///
/// When `concurrent` feature is enabled, offsets are computed in multiple threads.
pub fn get_evaluation_offsets<E: FieldElement>(
    poly_size: usize,
    blowup_factor: usize,
    domain_offset: E::BaseField,
) -> Vec<E::BaseField> {
    let domain_size = poly_size * blowup_factor;
    let g = E::BaseField::get_root_of_unity(domain_size.ilog2());

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
    offsets.chunks_mut(poly_size).enumerate().for_each(compute_offsets);

    #[cfg(feature = "concurrent")]
    offsets.par_chunks_mut(poly_size).enumerate().for_each(compute_offsets);

    offsets
}

/// Returns matrix segments constructed by evaluating polynomials in the specified matrix over the
/// domain defined by twiddles and offsets.
pub fn build_segments<E: FieldElement, const N: usize>(
    polys: &ColMatrix<E>,
    twiddles: &[E::BaseField],
    offsets: &[E::BaseField],
) -> Vec<Segment<E::BaseField, N>> {
    assert!(N > 0, "batch size N must be greater than zero");
    debug_assert_eq!(polys.num_rows(), twiddles.len() * 2);
    debug_assert_eq!(offsets.len() % polys.num_rows(), 0);

    let num_segments = if polys.num_base_cols() % N == 0 {
        polys.num_base_cols() / N
    } else {
        polys.num_base_cols() / N + 1
    };

    (0..num_segments)
        .map(|i| Segment::new(polys, i * N, offsets, twiddles))
        .collect()
}

/// Transposes a vector of segments into a single vector of fixed-size arrays.
///
/// When `concurrent` feature is enabled, transposition is performed in multiple threads.
fn transpose<B: StarkField, const N: usize>(mut segments: Vec<Segment<B, N>>) -> Vec<[B; N]> {
    let num_rows = segments[0].num_rows();
    let num_segs = segments.len();
    let result_len = num_rows * num_segs;

    // if there is only one segment, there is nothing to transpose as it is already in row
    // major form
    if segments.len() == 1 {
        return segments.remove(0).into_data();
    }

    // allocate memory to hold the transposed result;
    // TODO: investigate transposing in-place
    let mut result = unsafe { uninit_vector::<[B; N]>(result_len) };

    // determine number of batches in which transposition will be preformed; if `concurrent`
    // feature is not enabled, the number of batches will always be 1
    let num_batches = get_num_batches(result_len);
    let rows_per_batch = num_rows / num_batches;

    // define a closure for transposing a given batch
    let transpose_batch = |(batch_idx, batch): (usize, &mut [[B; N]])| {
        let row_offset = batch_idx * rows_per_batch;
        for i in 0..rows_per_batch {
            let row_idx = i + row_offset;
            for j in 0..num_segs {
                let v = &segments[j][row_idx];
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
    utils::rayon::current_num_threads().next_power_of_two() * 2
}
