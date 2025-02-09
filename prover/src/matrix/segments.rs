// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::ops::Deref;

use math::{fft::fft_inputs::FftInputs, FieldElement, StarkField};
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::uninit_vector;

use super::ColMatrix;

// CONSTANTS
// ================================================================================================

/// Segments with domain sizes under this number will be evaluated in a single thread.
const MIN_CONCURRENT_SIZE: usize = 1024;

// SEGMENT OF ROW-MAJOR MATRIX
// ================================================================================================

/// A set of columns of a matrix stored in row-major form.
///
/// The rows are stored in a single vector where each element is an array of size `N`. A segment
/// can store [StarkField] elements only, but can be instantiated from a [Matrix] of any extension
/// of the specified [StarkField]. In such a case, extension field elements are decomposed into
/// base field elements and then added to the segment.
#[derive(Clone, Debug)]
pub struct Segment<B: StarkField, const N: usize> {
    data: Vec<[B; N]>,
}

impl<B: StarkField, const N: usize> Segment<B, N> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Instantiates a new [Segment] by evaluating polynomials from the provided [ColMatrix]
    /// starting at the specified offset.
    ///
    /// The offset is assumed to be an offset into the view of the matrix where extension field
    /// elements are decomposed into base field elements. This offset must be compatible with the
    /// values supplied into [Matrix::get_base_element()] method.
    ///
    /// Evaluation is performed over the domain specified by the provided twiddles and offsets.
    ///
    /// # Panics
    /// Panics if:
    /// - `poly_offset` greater than or equal to the number of base field columns in `polys`.
    /// - Number of offsets is not a power of two.
    /// - Number of offsets is smaller than or equal to the polynomial size.
    /// - The number of twiddles is not half the size of the polynomial size.
    pub fn new<E>(polys: &ColMatrix<E>, poly_offset: usize, offsets: &[B], twiddles: &[B]) -> Self
    where
        E: FieldElement<BaseField = B>,
    {
        let poly_size = polys.num_rows();
        let domain_size = offsets.len();
        assert!(domain_size.is_power_of_two());
        assert!(domain_size > poly_size);
        assert_eq!(poly_size, twiddles.len() * 2);
        assert!(poly_offset < polys.num_base_cols());

        // allocate memory for the segment
        let data = if polys.num_base_cols() - poly_offset >= N {
            // if we will fill the entire segment, we allocate uninitialized memory
            unsafe { uninit_vector::<[B; N]>(domain_size) }
        } else {
            // but if some columns in the segment will remain unfilled, we allocate memory
            // initialized to zeros to make sure we don't end up with memory with
            // undefined values
            vec![[B::ZERO; N]; domain_size]
        };

        Self::new_with_buffer(data, polys, poly_offset, offsets, twiddles)
    }

    /// Instantiates a new [Segment] using the provided data buffer by evaluating polynomials in
    /// the [ColMatrix] starting at the specified offset.
    ///
    /// The offset is assumed to be an offset into the view of the matrix where extension field
    /// elements are decomposed into base field elements. This offset must be compatible with the
    /// values supplied into [Matrix::get_base_element()] method.
    ///
    /// Evaluation is performed over the domain specified by the provided twiddles and offsets.
    ///
    /// # Panics
    /// Panics if:
    /// - `poly_offset` greater than or equal to the number of base field columns in `polys`.
    /// - Number of offsets is not a power of two.
    /// - Number of offsets is smaller than or equal to the polynomial size.
    /// - The number of twiddles is not half the size of the polynomial size.
    /// - Number of offsets is smaller than the length of the data buffer
    pub fn new_with_buffer<E>(
        data_buffer: Vec<[B; N]>,
        polys: &ColMatrix<E>,
        poly_offset: usize,
        offsets: &[B],
        twiddles: &[B],
    ) -> Self
    where
        E: FieldElement<BaseField = B>,
    {
        let poly_size = polys.num_rows();
        let domain_size = offsets.len();
        let mut data = data_buffer;

        assert!(domain_size.is_power_of_two());
        assert!(domain_size > poly_size);
        assert_eq!(poly_size, twiddles.len() * 2);
        assert!(poly_offset < polys.num_base_cols());
        assert_eq!(data.len(), domain_size);

        // determine the number of polynomials to add to this segment; this number can be either N,
        // or smaller than N when there are fewer than N polynomials remaining to be processed
        let num_polys_remaining = polys.num_base_cols() - poly_offset;
        let num_polys = if num_polys_remaining < N {
            num_polys_remaining
        } else {
            N
        };

        // evaluate the polynomials either in a single thread or multiple threads, depending
        // on whether `concurrent` feature is enabled and domain size is greater than 1024;

        if cfg!(feature = "concurrent") && domain_size >= MIN_CONCURRENT_SIZE {
            #[cfg(feature = "concurrent")]
            data.par_chunks_mut(poly_size).zip(offsets.par_chunks(poly_size)).for_each(
                |(d_chunk, o_chunk)| {
                    // TODO: investigate multi-threaded copy
                    if num_polys == N {
                        Self::copy_polys(d_chunk, polys, poly_offset, o_chunk);
                    } else {
                        Self::copy_polys_partial(d_chunk, polys, poly_offset, num_polys, o_chunk);
                    }
                    concurrent::split_radix_fft(d_chunk, twiddles);
                },
            );
            #[cfg(feature = "concurrent")]
            concurrent::permute(&mut data);
        } else {
            data.chunks_mut(poly_size).zip(offsets.chunks(poly_size)).for_each(
                |(d_chunk, o_chunk)| {
                    if num_polys == N {
                        Self::copy_polys(d_chunk, polys, poly_offset, o_chunk);
                    } else {
                        Self::copy_polys_partial(d_chunk, polys, poly_offset, num_polys, o_chunk);
                    }
                    d_chunk.fft_in_place(twiddles);
                },
            );
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

    /// Returns the underlying vector of arrays for this segment.
    pub fn into_data(self) -> Vec<[B; N]> {
        self.data
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Copies N polynomials starting at the specified base column offset (`poly_offset`) into the
    /// specified destination. Each polynomial coefficient is offset by the specified offset.
    fn copy_polys<E: FieldElement<BaseField = B>>(
        dest: &mut [[B; N]],
        polys: &ColMatrix<E>,
        poly_offset: usize,
        offsets: &[B],
    ) {
        for row_idx in 0..dest.len() {
            for i in 0..N {
                let coeff = polys.get_base_element(poly_offset + i, row_idx);
                dest[row_idx][i] = coeff * offsets[row_idx];
            }
        }
    }

    /// Similar to `clone_and_shift` method above, but copies `num_polys` polynomials instead of
    /// `N` polynomials.
    ///
    /// Assumes that `num_polys` is smaller than `N`.
    fn copy_polys_partial<E: FieldElement<BaseField = B>>(
        dest: &mut [[B; N]],
        polys: &ColMatrix<E>,
        poly_offset: usize,
        num_polys: usize,
        offsets: &[B],
    ) {
        debug_assert!(num_polys < N);
        for row_idx in 0..dest.len() {
            for i in 0..num_polys {
                let coeff = polys.get_base_element(poly_offset + i, row_idx);
                dest[row_idx][i] = coeff * offsets[row_idx];
            }
        }
    }
}

impl<B: StarkField, const N: usize> Deref for Segment<B, N> {
    type Target = Vec<[B; N]>;

    fn deref(&self) -> &Self::Target {
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
    use math::fft::permute_index;
    use utils::{iterators::*, rayon};

    use super::{FftInputs, StarkField};

    /// In-place recursive FFT with permuted output.
    /// Adapted from: https://github.com/0xProject/OpenZKP/tree/master/algebra/primefield/src/fft
    #[allow(clippy::needless_range_loop)]
    pub fn split_radix_fft<B: StarkField, const N: usize>(data: &mut [[B; N]], twiddles: &[B]) {
        // generator of the domain should be in the middle of twiddles
        let n = data.len();
        let g = twiddles[twiddles.len() / 2];
        debug_assert_eq!(g.exp((n as u32).into()), B::ONE);

        let inner_len = 1_usize << (n.ilog2() / 2);
        let outer_len = n / inner_len;
        let stretch = outer_len / inner_len;
        debug_assert!(outer_len == inner_len || outer_len == 2 * inner_len);
        debug_assert_eq!(outer_len * inner_len, n);

        // transpose inner x inner x stretch square matrix
        transpose_square_stretch(data, inner_len, stretch);

        // apply inner FFTs
        data.par_chunks_mut(outer_len)
            .for_each(|row| row.fft_in_place_raw(twiddles, stretch, stretch, 0));

        // transpose inner x inner x stretch square matrix
        transpose_square_stretch(data, inner_len, stretch);

        // apply outer FFTs
        data.par_chunks_mut(outer_len).enumerate().for_each(|(i, row)| {
            if i > 0 {
                let i = permute_index(inner_len, i);
                let inner_twiddle = g.exp_vartime((i as u32).into());
                let mut outer_twiddle = inner_twiddle;
                for element in row.iter_mut().skip(1) {
                    for col_idx in 0..N {
                        element[col_idx] *= outer_twiddle;
                    }
                    outer_twiddle *= inner_twiddle;
                }
            }
            row.fft_in_place(twiddles)
        });
    }

    // PERMUTATIONS
    // --------------------------------------------------------------------------------------------

    pub fn permute<T: Send>(v: &mut [T]) {
        let n = v.len();
        let num_batches = rayon::current_num_threads().next_power_of_two() * 2;
        let batch_size = n / num_batches;
        rayon::scope(|s| {
            for batch_idx in 0..num_batches {
                // create another mutable reference to the slice of values to use in a new thread;
                // this is OK because we never write the same positions in the slice from different
                // threads
                let values = unsafe { &mut *(&mut v[..] as *mut [T]) };
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

    fn transpose_square_stretch<T>(data: &mut [T], size: usize, stretch: usize) {
        assert_eq!(data.len(), size * size * stretch);
        match stretch {
            1 => transpose_square_1(data, size),
            2 => transpose_square_2(data, size),
            _ => unimplemented!("only stretch sizes 1 and 2 are supported"),
        }
    }

    fn transpose_square_1<T>(data: &mut [T], size: usize) {
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

    fn transpose_square_2<T>(data: &mut [T], size: usize) {
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
