// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Matrix;
use math::{fft::fft_inputs::FftInputs, FieldElement};
use utils::{collections::Vec, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// CONSTANTS
// ================================================================================================

/// Number of elements in row of a segment.
pub const SEGMENT_WIDTH: usize = 8;

/// Segments with domain sizes under this number will be evaluated in a single thread.
const MIN_CONCURRENT_SIZE: usize = 1024;

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
    data: Vec<[E; SEGMENT_WIDTH]>,
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
        let mut data = unsafe { uninit_vector::<[E; SEGMENT_WIDTH]>(domain_size) };

        // evaluate the polynomials either in a single thread or multiple threads, depending
        // on whether `concurrent` feature is enabled and domain size is greater than 1024;

        if cfg!(feature = "concurrent") && domain_size >= MIN_CONCURRENT_SIZE {
            #[cfg(feature = "concurrent")]
            data.par_chunks_mut(poly_size)
                .zip(offsets.par_chunks(poly_size))
                .for_each(|(d_chunk, o_chunk)| {
                    for row_idx in 0..poly_size {
                        for i in 0..SEGMENT_WIDTH {
                            let coeff = polys.get(poly_offset + i, row_idx);
                            d_chunk[row_idx][i] = coeff.mul_base(o_chunk[row_idx]);
                        }
                    }
                    concurrent::split_radix_fft(d_chunk, twiddles);
                });
            #[cfg(feature = "concurrent")]
            concurrent::permute(&mut data);
        } else {
            data.chunks_mut(poly_size)
                .zip(offsets.chunks(poly_size))
                .for_each(|(d_chunk, o_chunk)| {
                    for row_idx in 0..poly_size {
                        for i in 0..SEGMENT_WIDTH {
                            let coeff = polys.get(poly_offset + i, row_idx);
                            d_chunk[row_idx][i] = coeff.mul_base(o_chunk[row_idx]);
                        }
                    }
                    d_chunk.fft_in_place(twiddles);
                });
            data.permute();
        }

        Segment { data }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of rows in this segment.
    pub fn num_rows(&self) -> usize {
        self.data.len()
    }

    /// Returns the data in this segment as a slice of arrays.
    pub fn data(&self) -> &[[E; SEGMENT_WIDTH]] {
        &self.data
    }
}

// CONCURRENT FFT IMPLEMENTATION
// ================================================================================================

/// Multi-threaded implementations of FFT and permutation algorithms. These are very similar to
/// the functions implemented in `winter-math::fft::concurrent` module, but are adapted to work
/// with slices of element arrays.
#[cfg(feature = "concurrent")]
mod concurrent {
    use super::{FftInputs, FieldElement, SEGMENT_WIDTH};
    use math::fft::permute_index;
    use utils::{iterators::*, rayon};

    /// In-place recursive FFT with permuted output.
    /// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
    pub fn split_radix_fft<E: FieldElement>(
        data: &mut [[E; SEGMENT_WIDTH]],
        twiddles: &[E::BaseField],
    ) {
        // generator of the domain should be in the middle of twiddles
        let n = data.len();
        let g = twiddles[twiddles.len() / 2];
        debug_assert_eq!(g.exp((n as u32).into()), E::BaseField::ONE);

        let inner_len = 1_usize << (n.ilog2() / 2);
        let outer_len = n / inner_len;
        let stretch = outer_len / inner_len;
        debug_assert!(outer_len == inner_len || outer_len == 2 * inner_len);
        debug_assert_eq!(outer_len * inner_len, n);

        // transpose inner x inner x stretch square matrix
        transpose_square_stretch(data, inner_len, stretch);

        // apply inner FFTs
        data.par_chunks_mut(outer_len)
            .for_each(|row| row.fft_in_place_raw(&twiddles, stretch, stretch, 0));

        // transpose inner x inner x stretch square matrix
        transpose_square_stretch(data, inner_len, stretch);

        // apply outer FFTs
        data.par_chunks_mut(outer_len)
            .enumerate()
            .for_each(|(i, row)| {
                if i > 0 {
                    let i = permute_index(inner_len, i);
                    let inner_twiddle = g.exp_vartime((i as u32).into());
                    let mut outer_twiddle = inner_twiddle;
                    for element in row.iter_mut().skip(1) {
                        for col_idx in 0..SEGMENT_WIDTH {
                            element[col_idx] = element[col_idx].mul_base(outer_twiddle);
                        }
                        outer_twiddle = outer_twiddle * inner_twiddle;
                    }
                }
                row.fft_in_place(&twiddles)
            });
    }

    // PERMUTATIONS
    // --------------------------------------------------------------------------------------------

    pub fn permute<E: FieldElement>(v: &mut [[E; SEGMENT_WIDTH]]) {
        let n = v.len();
        let num_batches = rayon::current_num_threads().next_power_of_two() * 2;
        let batch_size = n / num_batches;
        rayon::scope(|s| {
            for batch_idx in 0..num_batches {
                // create another mutable reference to the slice of values to use in a new thread;
                // this is OK because we never write the same positions in the slice from different
                // threads
                let values = unsafe { &mut *(&mut v[..] as *mut [[E; SEGMENT_WIDTH]]) };
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

    // TRANSPOSING
    // --------------------------------------------------------------------------------------------

    fn transpose_square_stretch<E: FieldElement>(
        data: &mut [[E; SEGMENT_WIDTH]],
        size: usize,
        stretch: usize,
    ) {
        assert_eq!(data.len(), size * size * stretch);
        match stretch {
            1 => transpose_square_1(data, size),
            2 => transpose_square_2(data, size),
            _ => unimplemented!("only stretch sizes 1 and 2 are supported"),
        }
    }

    fn transpose_square_1<E: FieldElement>(data: &mut [[E; SEGMENT_WIDTH]], size: usize) {
        debug_assert_eq!(data.len(), size * size);
        debug_assert_eq!(size % 2, 0, "odd sizes are not supported");

        // iterate over upper-left triangle, working in 2x2 blocks
        // TODO: investigate concurrent implementation
        for row in (0..size).step_by(2) {
            let i = row * size + row;
            data.swap(i + 1, i + size);
            for col in (row..size).step_by(2).skip(1) {
                let i = row * size + col;
                let j = col * size + row;
                data.swap(i, j);
                data.swap(i + 1, j + size);
                data.swap(i + size, j + 1);
                data.swap(i + size + 1, j + size + 1);
            }
        }
    }

    fn transpose_square_2<E: FieldElement>(data: &mut [[E; SEGMENT_WIDTH]], size: usize) {
        debug_assert_eq!(data.len(), 2 * size * size);

        // iterate over upper-left triangle, working in 1x2 blocks
        // TODO: investigate concurrent implementation
        for row in 0..size {
            for col in (row..size).skip(1) {
                let i = (row * size + col) * 2;
                let j = (col * size + row) * 2;
                data.swap(i, j);
                data.swap(i + 1, j + 1);
            }
        }
    }
}
