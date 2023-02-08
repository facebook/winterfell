// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{cmp, iter::FusedIterator};
use std::time::Instant;

use crate::Matrix;

use math::{
    fft::{self, fft_inputs::FftInputs, MIN_CONCURRENT_SIZE},
    FieldElement, StarkField,
};
use utils::{collections::Vec, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::rayon::{
    iter::plumbing::{bridge, Consumer, Producer, ProducerCallback, UnindexedConsumer},
    prelude::*,
};

use rayon::{
    iter::plumbing::{bridge, Consumer, Producer, ProducerCallback, UnindexedConsumer},
    prelude::*,
};

#[macro_export]
macro_rules! iter_mut {
    ($e: expr) => {{
        // #[cfg(feature = "concurrent")]
        // let result = $e.par_iter_mut();

        // #[cfg(not(feature = "concurrent"))]
        let result = $e.iter_mut();

        result
    }};
}

// CONSTANTS
// ================================================================================================

pub const ARR_SIZE: usize = 8;

// RowMatrix MATRIX
// ================================================================================================

#[derive(Clone, Debug)]
pub struct RowMatrix<E>
where
    E: FieldElement,
{
    data: Vec<[E; ARR_SIZE]>,
}

impl<E> RowMatrix<E>
where
    E: FieldElement,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub fn new(data: Vec<[E; ARR_SIZE]>) -> Self {
        Self { data }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        ARR_SIZE
    }

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.data.len()
    }

    /// Returns the data in this matrix as a mutable slice of arrays.
    pub fn as_data_mut(&mut self) -> &mut [[E; ARR_SIZE]] {
        &mut self.data
    }

    /// Returns the data in this matrix as a slice of arrays.
    pub fn as_data(&self) -> &[[E; ARR_SIZE]] {
        &self.data
    }

    /// Returns a reference to the row at the specified index.
    pub fn get_row(&self, row_idx: usize) -> &[E] {
        assert!(row_idx < self.num_rows());
        &self.data[row_idx]
    }

    /// Returns a mutable reference to the row at the specified index.
    pub fn get_row_mut(&mut self, row_idx: usize) -> &mut [E] {
        assert!(row_idx < self.num_rows());
        &mut self.data[row_idx]
    }
}

/// Evaluates polynomial `p` over the domain of length `p.len()` * `blowup_factor` shifted by
/// `domain_offset` in the field specified `B` using the FFT algorithm and returns the result.
pub fn evaluate_poly_with_offset<E>(p: &mut RowMatrix<E>, twiddles: &[E::BaseField])
where
    E: FieldElement,
{
    p.fft_in_place(twiddles);
    p.permute()
}

// #[cfg(feature = "concurrent")]
/// Evaluates polynomial `p` over the domain of length `p.len()` * `blowup_factor` shifted by
/// `domain_offset` in the field specified `B` using the FFT algorithm and returns the result.
///
/// This function is only available when the `concurrent` feature is enabled.
pub fn evaluate_poly_with_offset_concurrent<E>(p: &mut RowMatrix<E>, twiddles: &[E::BaseField])
where
    E: FieldElement,
{
    p.split_radix_fft(twiddles);
    p.permute_concurrent()
}

/// Implementation of `FftInputs` for `RowMatrix`.
impl<E> FftInputs<E> for RowMatrix<E>
where
    E: FieldElement,
{
    type ChunkItem<'b> = RowMatrixRef<'b, E> where Self: 'b;
    type ParChunksMut<'c> = MatrixChunksMut<'c, E> where Self: 'c;

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

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField, num_skip: usize) {
        let increment = E::from(increment);
        let mut offset = E::from(offset);
        for row_idx in num_skip..self.len() {
            // apply on index 0.
            self.data[row_idx][0] *= offset;

            // apply on index 1.
            self.data[row_idx][1] *= offset;

            // apply on index 2.
            self.data[row_idx][2] *= offset;

            // apply on index 3.
            self.data[row_idx][3] *= offset;

            // apply on index 4.
            self.data[row_idx][4] *= offset;

            // apply on index 5.
            self.data[row_idx][5] *= offset;

            // apply on index 6.
            self.data[row_idx][6] *= offset;

            // apply on index 7.
            self.data[row_idx][7] *= offset;

            offset *= increment;
        }
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);

        for row_idx in 0..self.len() {
            // apply on index 0.
            self.data[row_idx][0] *= offset;

            // apply on index 1.
            self.data[row_idx][1] *= offset;

            // apply on index 2.
            self.data[row_idx][2] *= offset;

            // apply on index 3.
            self.data[row_idx][3] *= offset;

            // apply on index 4.
            self.data[row_idx][4] *= offset;

            // apply on index 5.
            self.data[row_idx][5] *= offset;

            // apply on index 6.
            self.data[row_idx][6] *= offset;

            // apply on index 7.
            self.data[row_idx][7] *= offset;
        }
    }
    // #[cfg(feature = "concurrent")]
    fn par_mut_chunks(&mut self, chunk_size: usize) -> MatrixChunksMut<'_, E> {
        MatrixChunksMut {
            data: RowMatrixRef::new(&mut self.data),
            chunk_size,
        }
    }
}

pub struct RowMatrixRef<'a, E>
where
    E: FieldElement,
{
    data: &'a mut [[E; ARR_SIZE]],
}

impl<'a, E> RowMatrixRef<'a, E>
where
    E: FieldElement,
{
    /// Creates a new RowMatrixRef from a mutable reference to a slice of arrays.
    pub fn new(data: &'a mut [[E; ARR_SIZE]]) -> Self {
        Self { data }
    }

    /// Safe mutable slice cast to avoid unnecessary lifetime complexity.
    fn as_mut_slice(&mut self) -> &'a mut [[E; ARR_SIZE]] {
        let ptr = self.data as *mut [[E; ARR_SIZE]];
        // Safety: we still hold the mutable reference to the slice so no ownership rule is
        // violated.
        unsafe { ptr.as_mut().expect("the initial reference was not valid.") }
    }

    /// Splits the struct into two mutable struct at the given split point. Data of first
    /// chunk will contain elements at indices [0, split_point), and the second chunk
    /// will contain elements at indices [split_point, size).
    fn split_at_mut(&mut self, split_point: usize) -> (Self, Self) {
        let (left, right) = self.as_mut_slice().split_at_mut(split_point);
        let left = Self::new(left);
        let right = Self::new(right);
        (left, right)
    }
}

/// Implementation of `FftInputs` for `RowMatrix`.
impl<'a, E> FftInputs<E> for RowMatrixRef<'a, E>
where
    E: FieldElement,
{
    type ChunkItem<'b> = RowMatrixRef<'b, E> where Self: 'b;
    type ParChunksMut<'c> = MatrixChunksMut<'c, E> where Self: 'c;

    fn len(&self) -> usize {
        self.data.len()
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

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField, num_skip: usize) {
        let increment = E::from(increment);
        let mut offset = E::from(offset);
        for row_idx in num_skip..self.len() {
            // apply on index 0.
            self.data[row_idx][0] *= offset;

            // apply on index 1.
            self.data[row_idx][1] *= offset;

            // apply on index 2.
            self.data[row_idx][2] *= offset;

            // apply on index 3.
            self.data[row_idx][3] *= offset;

            // apply on index 4.
            self.data[row_idx][4] *= offset;

            // apply on index 5.
            self.data[row_idx][5] *= offset;

            // apply on index 6.
            self.data[row_idx][6] *= offset;

            // apply on index 7.
            self.data[row_idx][7] *= offset;

            offset *= increment;
        }
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);

        for row_idx in 0..self.len() {
            // apply on index 0.
            self.data[row_idx][0] *= offset;

            // apply on index 1.
            self.data[row_idx][1] *= offset;

            // apply on index 2.
            self.data[row_idx][2] *= offset;

            // apply on index 3.
            self.data[row_idx][3] *= offset;

            // apply on index 4.
            self.data[row_idx][4] *= offset;

            // apply on index 5.
            self.data[row_idx][5] *= offset;

            // apply on index 6.
            self.data[row_idx][6] *= offset;

            // apply on index 7.
            self.data[row_idx][7] *= offset;
        }
    }

    // #[cfg(feature = "concurrent")]
    fn par_mut_chunks(&mut self, chunk_size: usize) -> MatrixChunksMut<'_, E> {
        MatrixChunksMut {
            data: RowMatrixRef {
                data: self.as_mut_slice(),
            },
            chunk_size,
        }
    }
}

/// A mutable iterator over chunks of a mutable FftInputs. This struct is created
///  by the `chunks_mut` method on `FftInputs`.
pub struct MatrixChunksMut<'a, E>
where
    E: FieldElement,
{
    data: RowMatrixRef<'a, E>,
    chunk_size: usize,
}

impl<'a, E> ExactSizeIterator for MatrixChunksMut<'a, E>
where
    E: FieldElement,
{
    fn len(&self) -> usize {
        self.data.len()
    }
}

impl<'a, E> DoubleEndedIterator for MatrixChunksMut<'a, E>
where
    E: FieldElement,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.len() == 0 {
            return None;
        }
        let at = self.chunk_size.min(self.len());
        let (head, tail) = self.data.split_at_mut(at);
        self.data = head;
        Some(tail)
    }
}

impl<'a, E: FieldElement> Iterator for MatrixChunksMut<'a, E> {
    type Item = RowMatrixRef<'a, E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len() == 0 {
            return None;
        }
        let at = self.chunk_size.min(self.len());
        let (head, tail) = self.data.split_at_mut(at);
        self.data = tail;
        Some(head)
    }
}

// #[cfg(feature = "concurrent")]
/// Implement a parallel iterator for MatrixChunksMut. This is a parallel version
/// of the MatrixChunksMut iterator.
impl<'a, E> ParallelIterator for MatrixChunksMut<'a, E>
where
    E: FieldElement + Send,
{
    type Item = RowMatrixRef<'a, E>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        bridge(self, consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        Some(rayon::iter::IndexedParallelIterator::len(self))
    }
}

// #[cfg(feature = "concurrent")]
impl<'a, E> IndexedParallelIterator for MatrixChunksMut<'a, E>
where
    E: FieldElement + Send,
{
    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        let producer = ChunksMutProducer {
            chunk_size: self.chunk_size,
            data: self.data,
        };
        callback.callback(producer)
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        bridge(self, consumer)
    }

    fn len(&self) -> usize {
        self.data.len() / self.chunk_size
    }
}

// #[cfg(feature = "concurrent")]
struct ChunksMutProducer<'a, E>
where
    E: FieldElement,
{
    chunk_size: usize,
    data: RowMatrixRef<'a, E>,
}

// #[cfg(feature = "concurrent")]
impl<'a, E> Producer for ChunksMutProducer<'a, E>
where
    E: FieldElement,
{
    type Item = RowMatrixRef<'a, E>;
    type IntoIter = MatrixChunksMut<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        MatrixChunksMut {
            data: self.data,
            chunk_size: self.chunk_size,
        }
    }

    fn split_at(mut self, index: usize) -> (Self, Self) {
        let elem_index = cmp::min(index * self.chunk_size, self.data.len());
        let (left, right) = self.data.split_at_mut(elem_index);
        (
            ChunksMutProducer {
                chunk_size: self.chunk_size,
                data: left,
            },
            ChunksMutProducer {
                chunk_size: self.chunk_size,
                data: right,
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct Segment<E>
where
    E: FieldElement,
{
    matrix: Vec<RowMatrix<E>>,
}

impl<E> Segment<E>
where
    E: FieldElement,
{
    pub fn new(matrix: Vec<RowMatrix<E>>) -> Self {
        Self { matrix }
    }

    pub fn from_polys(polys: &Matrix<E>, blowup_factor: usize) -> Self {
        let row_width = polys.num_cols();
        let num_rows = polys.num_rows();

        let twiddles = fft::get_twiddles::<E::BaseField>(polys.num_rows() * blowup_factor);
        let domain_offset = E::BaseField::GENERATOR;

        let num_of_segments = row_width / ARR_SIZE;
        let mut row_matrices = Vec::with_capacity(num_of_segments);

        let mut offsets = Vec::with_capacity(num_rows);
        offsets.push(E::BaseField::ONE);
        for i in 1..num_rows {
            offsets.push(offsets[i - 1] * domain_offset);
        }
        for i in 0..num_of_segments {
            let segment = &polys.columns[i * ARR_SIZE..(i + 1) * ARR_SIZE];
            let mut result_vec_of_arrays =
                unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * blowup_factor) };

            segment.iter().enumerate().for_each(|(i, row)| {
                row.iter().enumerate().for_each(|(j, elem)| {
                    result_vec_of_arrays[(j)][i] = elem.mul_base(offsets[j]);
                })
            });

            let row_matrix = RowMatrix::new(result_vec_of_arrays);
            row_matrices.push(row_matrix);
        }

        if cfg!(feature = "concurrent") && polys.num_rows() >= MIN_CONCURRENT_SIZE {
            {
                iter_mut!(row_matrices).for_each(|segment| {
                    evaluate_poly_with_offset_concurrent(segment, &twiddles);
                });
            }
        } else {
            for segment in row_matrices.iter_mut() {
                evaluate_poly_with_offset(segment, &twiddles);
            }
            // iter_mut!(row_matrices).for_each(|segment| {
            //     evaluate_poly_with_offset_concurrent(segment, &twiddles);
            // });
        }
        // println!(
        //     "Time to evaluate row matrices: {:?}",
        //     time.elapsed().as_millis()
        // );
        Segment::new(row_matrices)
    }

    pub fn transpose_to_gpu_friendly_matrix(&self) -> RowMatrix<E> {
        let num_rows = self.matrix[0].num_rows();
        let num_cols = self.matrix[0].num_cols() * self.matrix.len();
        let mut result = unsafe { uninit_vector::<[E; ARR_SIZE]>(num_rows * num_cols / ARR_SIZE) };
        self.matrix.iter().enumerate().for_each(|(i, segment)| {
            (segment.as_data()).iter().enumerate().for_each(|(j, row)| {
                result[i * num_rows + j] = *row;
            })
        });
        RowMatrix { data: result }
    }

    pub fn iter(&self) -> SegmentIter<E> {
        SegmentIter::new(&self.matrix)
    }

    pub fn par_iter(&self) -> SegmentIter<E> {
        SegmentIter::new(&self.matrix)
    }

    pub fn iter_mut(&mut self) -> SegmentIterMut<E> {
        SegmentIterMut::new(&mut self.matrix)
    }

    pub fn par_iter_mut(&mut self) -> SegmentIterMut<E> {
        SegmentIterMut::new(&mut self.matrix)
    }

    pub fn len(&self) -> usize {
        self.matrix.len()
    }

    pub fn is_empty(&self) -> bool {
        self.matrix.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&RowMatrix<E>> {
        self.matrix.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut RowMatrix<E>> {
        self.matrix.get_mut(index)
    }

    pub fn push(&mut self, matrix: RowMatrix<E>) {
        self.matrix.push(matrix);
    }

    pub fn pop(&mut self) -> Option<RowMatrix<E>> {
        self.matrix.pop()
    }

    pub fn remove(&mut self, index: usize) -> Option<RowMatrix<E>> {
        Some(self.matrix.remove(index))
    }

    pub fn insert(&mut self, index: usize, matrix: RowMatrix<E>) {
        self.matrix.insert(index, matrix);
    }
}

// SECTION: ITERATORS
// ================================================================================================

// COLUMN ITERATOR
// ================================================================================================

pub struct SegmentIter<'a, E: FieldElement> {
    matrix: &'a [RowMatrix<E>],
    cursor: usize,
}

impl<'a, E: FieldElement> SegmentIter<'a, E> {
    pub fn new(matrix: &'a Vec<RowMatrix<E>>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for SegmentIter<'a, E> {
    type Item = &'a RowMatrix<E>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix.len() - self.cursor {
            0 => None,
            _ => {
                let column = &self.matrix[self.cursor];
                self.cursor += 1;
                Some(column)
            }
        }
    }
}

impl<'a, E> DoubleEndedIterator for SegmentIter<'a, E>
where
    E: FieldElement,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.cursor {
            0 => None,
            _ => {
                self.cursor -= 1;
                Some(&self.matrix[self.cursor])
            }
        }
    }
}

impl<'a, E: FieldElement> ExactSizeIterator for SegmentIter<'a, E> {
    fn len(&self) -> usize {
        self.matrix.len()
    }
}

impl<'a, E: FieldElement> FusedIterator for SegmentIter<'a, E> {}

// MUTABLE COLUMN ITERATOR
// ================================================================================================

pub struct SegmentIterMut<'a, E: FieldElement> {
    matrix: &'a mut [RowMatrix<E>],
    cursor: usize,
}

impl<'a, E: FieldElement> SegmentIterMut<'a, E> {
    pub fn new(matrix: &'a mut Vec<RowMatrix<E>>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for SegmentIterMut<'a, E> {
    type Item = &'a mut RowMatrix<E>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix.len() - self.cursor {
            0 => None,
            _ => {
                let segment = &self.matrix[self.cursor];
                self.cursor += 1;

                // unsafe code to get a mutable reference to the segment.
                // this is safe because we are the only one with a mutable reference to the matrix
                // and we are not moving the segment out of the matrix.
                let segment_ptr = segment as *const RowMatrix<E> as *mut RowMatrix<E>;
                Some(unsafe { &mut *segment_ptr })
            }
        }
    }
}

impl<'a, E: FieldElement> ExactSizeIterator for SegmentIterMut<'a, E> {
    fn len(&self) -> usize {
        self.matrix.len()
    }
}

impl<'a, E> DoubleEndedIterator for SegmentIterMut<'a, E>
where
    E: FieldElement,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.cursor {
            0 => None,
            _ => {
                self.cursor -= 1;
                let segment = &self.matrix[self.cursor];

                // unsafe code to get a mutable reference to the segment.
                // this is safe because we are the only one with a mutable reference to the matrix
                // and we are not moving the segment out of the matrix.
                let segment_ptr = segment as *const RowMatrix<E> as *mut RowMatrix<E>;
                Some(unsafe { &mut *segment_ptr })
            }
        }
    }
}

impl<'a, E: FieldElement> FusedIterator for SegmentIterMut<'a, E> {}

// PARALLEL ITERATORS
// ================================================================================================

impl<'a, E> ParallelIterator for SegmentIterMut<'a, E>
where
    E: FieldElement + Send,
{
    type Item = &'a mut RowMatrix<E>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        bridge(self, consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        Some(rayon::iter::IndexedParallelIterator::len(self))
    }
}

// #[cfg(feature = "concurrent")]
impl<'a, E> IndexedParallelIterator for SegmentIterMut<'a, E>
where
    E: FieldElement + Send,
{
    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        let producer = SegmentMutProducer {
            matrix: self.matrix,
            cursor: self.cursor,
        };
        callback.callback(producer)
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        bridge(self, consumer)
    }

    fn len(&self) -> usize {
        self.matrix.len()
    }
}

// #[cfg(feature = "concurrent")]
struct SegmentMutProducer<'a, E>
where
    E: FieldElement,
{
    matrix: &'a mut [RowMatrix<E>],
    cursor: usize,
}

// #[cfg(feature = "concurrent")]
impl<'a, E> Producer for SegmentMutProducer<'a, E>
where
    E: FieldElement,
{
    type Item = &'a mut RowMatrix<E>;
    type IntoIter = SegmentIterMut<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        SegmentIterMut {
            matrix: self.matrix,
            cursor: self.cursor,
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let (left, right) = self.matrix.split_at_mut(index);

        (
            SegmentMutProducer {
                matrix: left,
                cursor: self.cursor,
            },
            SegmentMutProducer {
                matrix: right,
                cursor: self.cursor,
            },
        )
    }
}

impl<'a, E> ParallelIterator for SegmentIter<'a, E>
where
    E: FieldElement + Send,
{
    type Item = &'a RowMatrix<E>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: UnindexedConsumer<Self::Item>,
    {
        bridge(self, consumer)
    }

    fn opt_len(&self) -> Option<usize> {
        Some(rayon::iter::IndexedParallelIterator::len(self))
    }
}

// #[cfg(feature = "concurrent")]
impl<'a, E> IndexedParallelIterator for SegmentIter<'a, E>
where
    E: FieldElement + Send,
{
    fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
        let producer = SegmentProducer {
            matrix: self.matrix,
            cursor: self.cursor,
        };
        callback.callback(producer)
    }

    fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
        bridge(self, consumer)
    }

    fn len(&self) -> usize {
        self.matrix.len()
    }
}

// #[cfg(feature = "concurrent")]
struct SegmentProducer<'a, E>
where
    E: FieldElement,
{
    matrix: &'a [RowMatrix<E>],
    cursor: usize,
}

// #[cfg(feature = "concurrent")]
impl<'a, E> Producer for SegmentProducer<'a, E>
where
    E: FieldElement,
{
    type Item = &'a RowMatrix<E>;
    type IntoIter = SegmentIter<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        SegmentIter {
            matrix: self.matrix,
            cursor: self.cursor,
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        let (left, right) = self.matrix.split_at(index);

        (
            SegmentProducer {
                matrix: left,
                cursor: self.cursor,
            },
            SegmentProducer {
                matrix: right,
                cursor: self.cursor,
            },
        )
    }
}
