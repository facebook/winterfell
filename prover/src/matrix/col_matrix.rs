// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::{iter::FusedIterator, slice};

use crypto::{ElementHasher, VectorCommitment};
use math::{fft, polynom, FieldElement};
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{batch_iter_mut, iter, iter_mut, uninit_vector};

use crate::StarkDomain;

// COLUMN-MAJOR MATRIX
// ================================================================================================

/// A two-dimensional matrix of field elements arranged in column-major order.
///
/// This struct is used as a backing type for many objects manipulated by the prover. The matrix
/// itself does not assign any contextual meaning to the values stored in it. For example, columns
/// may contain evaluations of polynomials, or polynomial coefficients, or really anything else.
/// However, the matrix does expose a number of methods which make assumptions about the underlying
/// data.
///
/// A matrix imposes the following restrictions on its content:
/// - A matrix must consist of at least 1 column and at least 2 rows.
/// - All columns must be of the same length.
/// - Number of rows must be a power of two.
#[derive(Debug, Clone)]
pub struct ColMatrix<E: FieldElement> {
    columns: Vec<Vec<E>>,
}

impl<E: FieldElement> ColMatrix<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Matrix] instantiated with the data from the specified columns.
    ///
    /// # Panics
    /// Panics if:
    /// * The provided vector of columns is empty.
    /// * Not all of the columns have the same number of elements.
    /// * Number of rows is smaller than or equal to 1.
    /// * Number of rows is not a power of two.
    pub fn new(columns: Vec<Vec<E>>) -> Self {
        assert!(!columns.is_empty(), "a matrix must contain at least one column");
        let num_rows = columns[0].len();
        assert!(num_rows > 1, "number of rows in a matrix must be greater than one");
        assert!(num_rows.is_power_of_two(), "number of rows in a matrix must be a power of 2");
        for column in columns.iter().skip(1) {
            assert_eq!(column.len(), num_rows, "all matrix columns must have the same length");
        }

        Self { columns }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        self.columns.len()
    }

    /// Returns the number of base field columns in this matrix.
    ///
    /// The number of base field columns is defined as the number of columns multiplied by the
    /// extension degree of field elements contained in this matrix.
    pub fn num_base_cols(&self) -> usize {
        self.num_cols() * E::EXTENSION_DEGREE
    }

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.columns[0].len()
    }

    /// Returns the element located at the specified column and row indexes in this matrix.
    ///
    /// # Panics
    /// Panics if either `col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn get(&self, col_idx: usize, row_idx: usize) -> E {
        self.columns[col_idx][row_idx]
    }

    /// Returns base field elements located at the specified column and row indexes in this matrix.
    ///
    /// For STARK fields, `base_col_idx` is the same as `col_idx` used in `Self::get` method. For
    /// extension fields, each column in the matrix is viewed as 2 or more columns in the base
    /// field.
    ///
    /// Thus, for example, if we are in a degree 2 extension field, `base_col_idx = 0` would refer
    /// to the first base element of the first column, `base_col_idx = 1` would refer to the second
    /// base element of the first column, `base_col_idx = 2` would refer to the first base element
    /// of the second column etc.
    ///
    /// # Panics
    /// Panics if either `base_col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn get_base_element(&self, base_col_idx: usize, row_idx: usize) -> E::BaseField {
        let (col_idx, elem_idx) =
            (base_col_idx / E::EXTENSION_DEGREE, base_col_idx % E::EXTENSION_DEGREE);
        self.columns[col_idx][row_idx].base_element(elem_idx)
    }

    /// Set the cell in this matrix at the specified column and row indexes to the provided value.
    ///
    /// # Panics
    /// Panics if either `col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn set(&mut self, col_idx: usize, row_idx: usize, value: E) {
        self.columns[col_idx][row_idx] = value;
    }

    /// Returns a reference to the column at the specified index.
    pub fn get_column(&self, col_idx: usize) -> &[E] {
        &self.columns[col_idx]
    }

    /// Returns a reference to the column at the specified index.
    pub fn get_column_mut(&mut self, col_idx: usize) -> &mut [E] {
        &mut self.columns[col_idx]
    }

    /// Copies values of all columns at the specified row into the specified row slice.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this matrix.
    pub fn read_row_into(&self, row_idx: usize, row: &mut [E]) {
        for (column, value) in self.columns.iter().zip(row.iter_mut()) {
            *value = column[row_idx];
        }
    }

    /// Updates a row in this matrix at the specified index to the provided data.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this matrix.
    pub fn update_row(&mut self, row_idx: usize, row: &[E]) {
        for (column, &value) in self.columns.iter_mut().zip(row) {
            column[row_idx] = value;
        }
    }

    /// Merges a column to the end of the matrix provided its length matches the matrix.
    ///
    /// # Panics
    /// Panics if the column has a different length to other columns in the matrix.
    pub fn merge_column(&mut self, column: Vec<E>) {
        if let Some(first_column) = self.columns.first() {
            assert_eq!(first_column.len(), column.len());
        }
        self.columns.push(column);
    }

    /// Removes a column of the matrix given its index.
    ///
    /// # Panics
    /// Panics if the column index is out of range.
    pub fn remove_column(&mut self, index: usize) -> Vec<E> {
        assert!(index < self.num_cols(), "column index out of range");
        self.columns.remove(index)
    }

    // ITERATION
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the columns of this matrix.
    pub fn columns(&self) -> ColumnIter<E> {
        ColumnIter::new(self)
    }

    /// Returns a mutable iterator over the columns of this matrix.
    pub fn columns_mut(&mut self) -> ColumnIterMut<E> {
        ColumnIterMut::new(self)
    }

    // POLYNOMIAL METHODS
    // --------------------------------------------------------------------------------------------

    /// Interpolates columns of the matrix into polynomials in coefficient form and returns the
    /// result.
    ///
    /// The interpolation is performed as follows:
    /// * Each column of the matrix is interpreted as evaluations of degree `num_rows - 1`
    ///   polynomial over a subgroup of size `num_rows`.
    /// * Then each column is interpolated using iFFT algorithm into a polynomial in coefficient
    ///   form.
    /// * The resulting polynomials are returned as a single matrix where each column contains
    ///   coefficients of a degree `num_rows - 1` polynomial.
    pub fn interpolate_columns(&self) -> Self {
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(self.num_rows());
        let columns = iter!(self.columns)
            .map(|evaluations| {
                let mut column = evaluations.clone();
                fft::interpolate_poly(&mut column, &inv_twiddles);
                column
            })
            .collect();
        Self { columns }
    }

    /// Interpolates columns of the matrix into polynomials in coefficient form and returns the
    /// result. The input matrix is consumed in the process.
    ///
    /// The interpolation is performed as follows:
    /// * Each column of the matrix is interpreted as evaluations of degree `num_rows - 1`
    ///   polynomial over a subgroup of size `num_rows`.
    /// * Then each column is interpolated (in place) using iFFT algorithm into a polynomial in
    ///   coefficient form.
    /// * The resulting polynomials are returned as a single matrix where each column contains
    ///   coefficients of a degree `num_rows - 1` polynomial.
    pub fn interpolate_columns_into(mut self) -> Self {
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(self.num_rows());
        iter_mut!(self.columns).for_each(|column| fft::interpolate_poly(column, &inv_twiddles));
        self
    }

    /// Evaluates polynomials contained in the columns of this matrix over the specified domain
    /// and returns the result.
    ///
    /// The evaluation is done as follows:
    /// * Each column of the matrix is interpreted as coefficients of degree `num_rows - 1`
    ///   polynomial.
    /// * These polynomials are evaluated over the LDE domain defined by the specified [StarkDomain]
    ///   using FFT algorithm. The domain specification includes the size of the subgroup as well as
    ///   the domain offset (to define a coset).
    /// * The resulting evaluations are returned in a new Matrix.
    pub fn evaluate_columns_over(&self, domain: &StarkDomain<E::BaseField>) -> Self {
        let columns = iter!(self.columns)
            .map(|poly| {
                fft::evaluate_poly_with_offset(
                    poly,
                    domain.trace_twiddles(),
                    domain.offset(),
                    domain.trace_to_lde_blowup(),
                )
            })
            .collect();
        Self { columns }
    }

    /// Evaluates polynomials contained in the columns of this matrix at a single point `x`.
    pub fn evaluate_columns_at<F>(&self, x: F) -> Vec<F>
    where
        F: FieldElement + From<E>,
    {
        iter!(self.columns).map(|p| polynom::eval(p, x)).collect()
    }

    // COMMITMENTS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to this matrix.
    ///
    /// The commitment is built as follows:
    /// * Each row of the matrix is hashed into a single digest of the specified hash function.
    /// * The resulting vector of digests is committed to using the specified vector commitment
    ///   scheme.
    /// * The resulting commitment is returned as the commitment to the entire matrix.
    pub fn commit_to_rows<H, V>(&self) -> V
    where
        H: ElementHasher<BaseField = E::BaseField>,
        V: VectorCommitment<H>,
    {
        // allocate vector to store row hashes
        let mut row_hashes = unsafe { uninit_vector::<H::Digest>(self.num_rows()) };

        // iterate though matrix rows, hashing each row; the hashing is done by first copying a
        // row into row_buf to avoid heap allocations, and then by applying the hash function to
        // the buffer.
        batch_iter_mut!(
            &mut row_hashes,
            128, // min batch size
            |batch: &mut [H::Digest], batch_offset: usize| {
                let mut row_buf = vec![E::ZERO; self.num_cols()];
                for (i, row_hash) in batch.iter_mut().enumerate() {
                    self.read_row_into(i + batch_offset, &mut row_buf);
                    *row_hash = H::hash_elements(&row_buf);
                }
            }
        );

        V::new(row_hashes).expect("failed to construct trace vector commitment")
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Returns the columns of this matrix as a list of vectors.
    ///
    /// TODO: replace this with an iterator.
    pub fn into_columns(self) -> Vec<Vec<E>> {
        self.columns
    }
}

// COLUMN ITERATOR
// ================================================================================================

/// Iterator over columns of [ColMatrix].
pub struct ColumnIter<'a, E: FieldElement> {
    matrix: Option<&'a ColMatrix<E>>,
    cursor: usize,
}

impl<'a, E: FieldElement> ColumnIter<'a, E> {
    pub fn new(matrix: &'a ColMatrix<E>) -> Self {
        Self { matrix: Some(matrix), cursor: 0 }
    }

    pub fn empty() -> Self {
        Self { matrix: None, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for ColumnIter<'a, E> {
    type Item = &'a [E];

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix {
            Some(matrix) => match matrix.num_cols() - self.cursor {
                0 => None,
                _ => {
                    let column = matrix.get_column(self.cursor);
                    self.cursor += 1;
                    Some(column)
                },
            },
            None => None,
        }
    }
}

impl<E: FieldElement> ExactSizeIterator for ColumnIter<'_, E> {
    fn len(&self) -> usize {
        self.matrix.map(|matrix| matrix.num_cols()).unwrap_or_default()
    }
}

impl<E: FieldElement> FusedIterator for ColumnIter<'_, E> {}

impl<E: FieldElement> Default for ColumnIter<'_, E> {
    fn default() -> Self {
        Self::empty()
    }
}

// MUTABLE COLUMN ITERATOR
// ================================================================================================

/// Iterator over mutable columns of [ColMatrix].
pub struct ColumnIterMut<'a, E: FieldElement> {
    matrix: &'a mut ColMatrix<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> ColumnIterMut<'a, E> {
    pub fn new(matrix: &'a mut ColMatrix<E>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for ColumnIterMut<'a, E> {
    type Item = &'a mut [E];

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix.num_cols() - self.cursor {
            0 => None,
            _ => {
                let column = self.matrix.get_column_mut(self.cursor);
                self.cursor += 1;

                // this is needed to get around mutable iterator lifetime issues; this is safe
                // because the iterator can never yield a reference to the same column twice
                let p = column.as_ptr();
                let len = column.len();
                Some(unsafe { slice::from_raw_parts_mut(p as *mut E, len) })
            },
        }
    }
}

impl<E: FieldElement> ExactSizeIterator for ColumnIterMut<'_, E> {
    fn len(&self) -> usize {
        self.matrix.num_cols()
    }
}

impl<E: FieldElement> FusedIterator for ColumnIterMut<'_, E> {}
