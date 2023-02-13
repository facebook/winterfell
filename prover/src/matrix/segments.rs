// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::iter::FusedIterator;
use math::{fft::fft_inputs::FftInputs, FieldElement};
use utils::collections::Vec;

// CONSTANTS
// ================================================================================================

pub const ARR_SIZE: usize = 8;

// SEGMENT OF ROWMAJOR MATRIX
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
pub struct Segment<E>
where
    E: FieldElement,
{
    data: Vec<[E; ARR_SIZE]>,
}

#[allow(dead_code)]
impl<E> Segment<E>
where
    E: FieldElement,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new segment of a row-major matrix from the specified data.
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
    ///
    /// # Panics
    /// Panics if the specified row index is out of bounds.
    pub fn get_row(&self, row_idx: usize) -> &[E; ARR_SIZE] {
        assert!(row_idx < self.num_rows());
        &self.data[row_idx]
    }

    /// Returns a mutable reference to the row at the specified index.
    ///
    /// # Panics
    /// Panics if the specified row index is out of bounds.
    pub fn get_row_mut(&mut self, row_idx: usize) -> &mut [E; ARR_SIZE] {
        assert!(row_idx < self.num_rows());
        &mut self.data[row_idx]
    }

    /// Evaluates the segment `p` over the domain of length `p.len()` using the FFT algorithm
    /// and returns the result. The computation is performed in place.
    pub fn evaluate_poly(&mut self, twiddles: &[E::BaseField])
    where
        E: FieldElement,
    {
        self.fft_in_place(twiddles);
        self.permute()
    }
}

/// Implementation of `FftInputs` for `Segment`.
impl<E> FftInputs<E> for Segment<E>
where
    E: FieldElement,
{
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

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField) {
        let increment = E::from(increment);
        let mut offset = E::from(offset);
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
}

// SEGMENTS
// ================================================================================================

/// Represents a collection of Segment objects.
#[derive(Debug, Clone)]
pub struct Segments<E>
where
    E: FieldElement,
{
    matrix: Vec<Segment<E>>,
}

#[allow(dead_code)]
impl<E> Segments<E>
where
    E: FieldElement,
{
    /// Create a new segment from a matrix of polynomials.
    pub fn new(matrix: Vec<Segment<E>>) -> Self {
        Self { matrix }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a iterator over the segments.
    pub fn iter(&self) -> SegmentIter<E> {
        SegmentIter::new(&self.matrix)
    }

    /// Returns a mutable iterator over the segments.
    pub fn iter_mut(&mut self) -> SegmentIterMut<E> {
        SegmentIterMut::new(&mut self.matrix)
    }

    /// Returns a iterator over the segments.
    pub fn len(&self) -> usize {
        self.matrix.len()
    }

    /// Returns a iterator over the segments.
    pub fn is_empty(&self) -> bool {
        self.matrix.is_empty()
    }

    /// Returns row matrix segment at the given index.
    ///
    /// # Panics
    /// Panics if the index is out of bounds.
    pub fn get(&self, index: usize) -> Option<&Segment<E>> {
        self.matrix.get(index)
    }

    /// Returns mutable row matrix segment at the given index.
    ///
    /// # Panics
    /// Panics if the index is out of bounds.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Segment<E>> {
        self.matrix.get_mut(index)
    }

    /// Push a new segment to the end of the segment vector.
    ///
    /// # Panics
    /// Panics if the segment length does not match the length of the other segments.
    pub fn push(&mut self, segment: Segment<E>) {
        self.matrix.push(segment);
    }

    /// Removes the last segment from the segment vector and returns it, or None if it is empty.
    ///
    /// # Panics
    /// Panics if the segment length does not match the length of the other segments.
    pub fn pop(&mut self) -> Option<Segment<E>> {
        self.matrix.pop()
    }
}

// SECTION: ITERATORS
// ================================================================================================

// COLUMN ITERATOR
// ================================================================================================

pub struct SegmentIter<'a, E>
where
    E: FieldElement,
{
    matrix: &'a [Segment<E>],
    cursor: usize,
}

impl<'a, E> SegmentIter<'a, E>
where
    E: FieldElement,
{
    pub fn new(matrix: &'a Vec<Segment<E>>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E> Iterator for SegmentIter<'a, E>
where
    E: FieldElement,
{
    type Item = &'a Segment<E>;

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

impl<'a, E> ExactSizeIterator for SegmentIter<'a, E>
where
    E: FieldElement,
{
    fn len(&self) -> usize {
        self.matrix.len()
    }
}

impl<'a, E> FusedIterator for SegmentIter<'a, E> where E: FieldElement {}

// MUTABLE COLUMN ITERATOR
// ================================================================================================

pub struct SegmentIterMut<'a, E>
where
    E: FieldElement,
{
    matrix: &'a mut [Segment<E>],
    cursor: usize,
}

impl<'a, E> SegmentIterMut<'a, E>
where
    E: FieldElement,
{
    pub fn new(matrix: &'a mut Vec<Segment<E>>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E> Iterator for SegmentIterMut<'a, E>
where
    E: FieldElement,
{
    type Item = &'a mut Segment<E>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix.len() - self.cursor {
            0 => None,
            _ => {
                let segment = &self.matrix[self.cursor];
                self.cursor += 1;

                // SAFETY: This is safe because the iterator can never yield a reference to the same
                // segment twice. This is needed to get around mutable iterator lifetime issues.
                let segment_ptr = segment as *const Segment<E> as *mut Segment<E>;
                Some(unsafe { &mut *segment_ptr })
            }
        }
    }
}

impl<'a, E> ExactSizeIterator for SegmentIterMut<'a, E>
where
    E: FieldElement,
{
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

                // SAFETY: This is safe because the iterator can never yield a reference to the same
                // segment twice. This is needed to get around mutable iterator lifetime issues.
                let segment_ptr = segment as *const Segment<E> as *mut Segment<E>;
                Some(unsafe { &mut *segment_ptr })
            }
        }
    }
}

impl<'a, E> FusedIterator for SegmentIterMut<'a, E> where E: FieldElement {}
