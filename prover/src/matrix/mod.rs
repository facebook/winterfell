// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::StarkDomain;
use core::{iter::FusedIterator, slice};
use crypto::{ElementHasher, MerkleTree};
use math::{
    fft::{self, fft_inputs::FftInputs, MIN_CONCURRENT_SIZE},
    log2, polynom, FieldElement, StarkField,
};
use utils::{batch_iter_mut, collections::Vec, iter, iter_mut, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

#[cfg(test)]
mod test;

// MATRIX
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
pub struct Matrix<E: FieldElement> {
    columns: Vec<Vec<E>>,
}

impl<E: FieldElement> Matrix<E> {
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
        assert!(
            !columns.is_empty(),
            "a matrix must contain at least one column"
        );
        let num_rows = columns[0].len();
        assert!(
            num_rows > 1,
            "number of rows in a matrix must be greater than one"
        );
        assert!(
            num_rows.is_power_of_two(),
            "number of rows in a matrix must be a power of 2"
        );
        for column in columns.iter().skip(1) {
            assert_eq!(
                column.len(),
                num_rows,
                "all matrix columns must have the same length"
            );
        }

        Self { columns }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        self.columns.len()
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
    /// * These polynomials are evaluated over the LDE domain defined by the specified
    ///   [StarkDomain] using FFT algorithm. The domain specification includes the size of the
    ///   subgroup as well as the domain offset (to define a coset).
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
    /// * The resulting values are used to built a binary Merkle tree such that each row digest
    ///   becomes a leaf in the tree. Thus, the number of leaves in the tree is equal to the
    ///   number of rows in the matrix.
    /// * The resulting Merkle tree is return as the commitment to the entire matrix.
    pub fn commit_to_rows<H>(&self) -> MerkleTree<H>
    where
        H: ElementHasher<BaseField = E::BaseField>,
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

        // build Merkle tree out of hashed rows
        MerkleTree::new(row_hashes).expect("failed to construct trace Merkle tree")
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

pub struct ColumnIter<'a, E: FieldElement> {
    matrix: &'a Matrix<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> ColumnIter<'a, E> {
    pub fn new(matrix: &'a Matrix<E>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for ColumnIter<'a, E> {
    type Item = &'a [E];

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix.num_cols() - self.cursor {
            0 => None,
            _ => {
                let column = self.matrix.get_column(self.cursor);
                self.cursor += 1;
                Some(column)
            }
        }
    }
}

impl<'a, E: FieldElement> ExactSizeIterator for ColumnIter<'a, E> {
    fn len(&self) -> usize {
        self.matrix.num_cols()
    }
}

impl<'a, E: FieldElement> FusedIterator for ColumnIter<'a, E> {}

// MUTABLE COLUMN ITERATOR
// ================================================================================================

pub struct ColumnIterMut<'a, E: FieldElement> {
    matrix: &'a mut Matrix<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> ColumnIterMut<'a, E> {
    pub fn new(matrix: &'a mut Matrix<E>) -> Self {
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
            }
        }
    }
}

impl<'a, E: FieldElement> ExactSizeIterator for ColumnIterMut<'a, E> {
    fn len(&self) -> usize {
        self.matrix.num_cols()
    }
}

impl<'a, E: FieldElement> FusedIterator for ColumnIterMut<'a, E> {}

// MULTI-MATRIX COLUMN ITERATOR
// ================================================================================================

pub struct MultiColumnIter<'a, E: FieldElement> {
    matrixes: &'a [Matrix<E>],
    m_cursor: usize,
    c_cursor: usize,
}

impl<'a, E: FieldElement> MultiColumnIter<'a, E> {
    pub fn new(matrixes: &'a [Matrix<E>]) -> Self {
        // make sure all matrixes have the same number of rows
        if !matrixes.is_empty() {
            let num_rows = matrixes[0].num_rows();
            for matrix in matrixes.iter().skip(1) {
                assert_eq!(
                    matrix.num_rows(),
                    num_rows,
                    "all matrixes must have the same number of rows"
                );
            }
        }

        Self {
            matrixes,
            m_cursor: 0,
            c_cursor: 0,
        }
    }
}

impl<'a, E: FieldElement> Iterator for MultiColumnIter<'a, E> {
    type Item = &'a [E];

    fn next(&mut self) -> Option<Self::Item> {
        if self.matrixes.is_empty() {
            return None;
        }
        let matrix = &self.matrixes[self.m_cursor];
        match matrix.num_cols() - self.c_cursor {
            0 => None,
            _ => {
                let column = matrix.get_column(self.c_cursor);
                self.c_cursor += 1;
                if self.c_cursor == matrix.num_cols() && self.m_cursor < self.matrixes.len() - 1 {
                    self.m_cursor += 1;
                    self.c_cursor = 0;
                }
                Some(column)
            }
        }
    }
}

impl<'a, E: FieldElement> ExactSizeIterator for MultiColumnIter<'a, E> {
    fn len(&self) -> usize {
        self.matrixes.iter().fold(0, |s, m| s + m.num_cols())
    }
}

impl<'a, E: FieldElement> FusedIterator for MultiColumnIter<'a, E> {}

// ROWMAJOR MATRIX
// ================================================================================================

pub struct RowMatrix<'a, E>
where
    E: FieldElement,
{
    data: &'a mut [E],
    row_width: usize,
}

impl<'a, E> RowMatrix<'a, E>
where
    E: FieldElement + 'a,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [RowMatrix] instantiated with the data from the specified columns.
    ///
    /// # Panics
    /// Panics if:
    /// * The provided rows of data is empty.
    /// * The remainder of the length of the data and the row width is not zero.
    /// * Number of rows is smaller than or equal to 1.
    /// * Number of rows is not a power of two.
    pub fn new(data: &'a mut [E], row_width: usize) -> Self {
        assert!(
            !data.is_empty(),
            "a matrix must contain at least one column"
        );
        assert!(
            data.len() % row_width == 0,
            "the length of the data should be a multiple of the row width"
        );
        assert!(
            data.len() / row_width > 1,
            "number of rows should be greater than 1"
        );
        assert!(
            (data.len() / row_width) & (data.len() / row_width - 1) == 0,
            "number of rows should be a power of 2"
        );

        Self { data, row_width }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this matrix.
    pub fn num_cols(&self) -> usize {
        self.row_width
    }

    /// Returns the number of rows in this matrix.
    pub fn num_rows(&self) -> usize {
        self.data.len() / self.row_width
    }

    /// Returns the data in this matrix as a mutable slice.
    pub fn as_data_mut(&mut self) -> &mut [E] {
        self.data
    }

    /// Returns the data in this matrix as a slice.
    pub fn as_data(&self) -> &[E] {
        self.data
    }

    /// Returns the element located at the specified column and row indexes in this matrix.
    ///
    /// # Panics
    /// Panics if either `col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn get(&self, col_idx: usize, row_idx: usize) -> E {
        self.data[row_idx * self.row_width + col_idx]
    }

    /// Set the cell in this matrix at the specified column and row indexes to the provided value.
    ///
    /// # Panics
    /// Panics if either `col_idx` or `row_idx` are out of bounds for this matrix.
    pub fn set(&mut self, col_idx: usize, row_idx: usize, value: E) {
        self.data[row_idx * self.row_width + col_idx] = value;
    }

    /// Returns a reference to the column at the specified index.
    pub fn get_column(&self, _col_idx: usize) -> &[E] {
        unimplemented!("not implemented yet")
    }

    /// Returns a reference to the column at the specified index.
    pub fn get_column_mut(&mut self, _col_idx: usize) -> &mut [E] {
        unimplemented!("not implemented yet")
    }

    /// Copies values of all columns at the specified row into the specified row slice.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this matrix.
    pub fn read_row_into(&self, row_idx: usize, row: &mut [E]) {
        row.copy_from_slice(&self.data[row_idx * self.row_width..(row_idx + 1) * self.row_width]);
    }

    /// Updates a row in this matrix at the specified index to the provided data.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this matrix.
    pub fn update_row(&mut self, row_idx: usize, row: &[E]) {
        self.data[row_idx * self.row_width..(row_idx + 1) * self.row_width].copy_from_slice(row);
    }

    /// Returns the columns of this matrix as a list of vectors.
    pub fn into_columns(&self) -> Vec<Vec<E>> {
        (0..self.num_cols()).map(|n| self.into_column(n)).collect()
    }

    /// Returns the column at the specified index.
    pub fn into_column(&self, index: usize) -> Vec<E> {
        self.data
            .iter()
            .copied()
            .skip(index)
            .step_by(self.num_cols())
            .collect()
    }

    // ITERATION
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the columns of this matrix.
    pub fn columns(&self) -> ColumnIter<E> {
        unimplemented!("not implemented yet")
    }

    /// Returns a mutable iterator over the columns of this matrix.
    pub fn columns_mut(&mut self) -> ColumnIterMut<E> {
        unimplemented!("not implemented yet")
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
    pub fn interpolate_columns(&mut self) -> Self {
        unimplemented!("not implemented yet")
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
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(self.num_rows());
        assert_eq!(
            self.len(),
            inv_twiddles.len() * 2,
            "invalid number of twiddles: expected {} but received {}",
            self.len() / 2,
            inv_twiddles.len()
        );
        assert!(
            log2(self.len()) <= E::BaseField::TWO_ADICITY,
            "multiplicative subgroup of size {} does not exist in the specified base field",
            self.len()
        );

        // when `concurrent` feature is enabled, run the concurrent version of interpolate_poly;
        // unless the number of evaluations is small, then don't bother with the concurrent version
        if cfg!(feature = "concurrent") && self.len() >= MIN_CONCURRENT_SIZE {
            #[cfg(feature = "concurrent")]
            concurrent::interpolate_poly(evaluations, inv_twiddles);
        } else {
            Self::interpolate_poly(&mut self, &inv_twiddles);
        }

        self
    }

    /// Evaluates polynomials contained in the columns of this matrix over the specified domain
    /// and returns the result.
    ///
    /// The evaluation is done as follows:
    /// * Each column of the matrix is interpreted as coefficients of degree `num_rows - 1`
    ///   polynomial.
    /// * These polynomials are evaluated over the LDE domain defined by the specified
    ///   [StarkDomain] using FFT algorithm. The domain specification includes the size of the
    ///   subgroup as well as the domain offset (to define a coset).
    /// * The resulting evaluations are returned in a new Matrix.
    pub fn evaluate_columns_over(&self, domain: &StarkDomain<E::BaseField>) -> Vec<E> {
        let blowup_factor = domain.trace_to_lde_blowup();
        let domain_offset = domain.offset();
        let twiddles = domain.trace_twiddles();

        assert!(
            self.len().is_power_of_two(),
            "number of coefficients must be a power of 2"
        );
        assert!(
            blowup_factor.is_power_of_two(),
            "blowup factor must be a power of 2"
        );
        assert_eq!(
            self.len(),
            twiddles.len() * 2,
            "invalid number of twiddles: expected {} but received {}",
            self.len() / 2,
            twiddles.len()
        );
        assert!(
            log2(self.len() * blowup_factor) <= E::BaseField::TWO_ADICITY,
            "multiplicative subgroup of size {} does not exist in the specified base field",
            self.len() * blowup_factor
        );
        assert_ne!(
            domain_offset,
            E::BaseField::ZERO,
            "domain offset cannot be zero"
        );

        let mut result = unsafe { uninit_vector(self.len() * self.num_rows() * blowup_factor) };
        let mut result_matrix = RowMatrix::new(result.as_mut_slice(), self.row_width);

        // when `concurrent` feature is enabled, run the concurrent version of the function; unless
        // the polynomial is small, then don't bother with the concurrent version
        if cfg!(feature = "concurrent") && self.len() >= MIN_CONCURRENT_SIZE {
            #[cfg(feature = "concurrent")]
            {
                result = concurrent::evaluate_poly_with_offset(
                    p,
                    twiddles,
                    domain_offset,
                    blowup_factor,
                );
            }
        } else {
            result = evaluate_poly_with_offset(
                &self,
                twiddles,
                domain_offset,
                blowup_factor,
                &mut result_matrix,
            );
        }

        // Cant return RowMatrix because result was created in this function. So we are returning a
        // Vec<E> instead. The caller of this function should convert it to a RowMatrix.
        result
    }

    /// Evaluates polynomials contained in the columns of this matrix at a single point `x`.
    pub fn evaluate_columns_at<F>(&self, x: F) -> Vec<F>
    where
        F: FieldElement + From<E>,
    {
        self.into_columns()
            .iter()
            .map(|p| polynom::eval(p, x))
            .collect()
    }

    // COMMITMENTS
    // --------------------------------------------------------------------------------------------

    /// Returns a commitment to this matrix.
    ///
    /// The commitment is built as follows:
    /// * Each row of the matrix is hashed into a single digest of the specified hash function.
    /// * The resulting values are used to built a binary Merkle tree such that each row digest
    ///   becomes a leaf in the tree. Thus, the number of leaves in the tree is equal to the
    ///   number of rows in the matrix.
    /// * The resulting Merkle tree is return as the commitment to the entire matrix.
    pub fn commit_to_rows<H>(&self) -> MerkleTree<H>
    where
        H: ElementHasher<BaseField = E::BaseField>,
    {
        // // allocate vector to store row hashes
        // let mut row_hashes = unsafe { uninit_vector::<H::Digest>(self.num_rows()) };

        // // iterate though matrix rows, hashing each row; the hashing is done by first copying a
        // // row into row_buf to avoid heap allocations, and then by applying the hash function to
        // // the buffer.
        // batch_iter_mut!(
        //     &mut row_hashes,
        //     128, // min batch size
        //     |batch: &mut [H::Digest], batch_offset: usize| {
        //         let mut row_buf = vec![E::ZERO; self.num_cols()];
        //         for (i, row_hash) in batch.iter_mut().enumerate() {
        //             self.read_row_into(i + batch_offset, &mut row_buf);
        //             *row_hash = H::hash_elements(&row_buf);
        //         }
        //     }
        // );

        // // build Merkle tree out of hashed rows
        // MerkleTree::new(row_hashes).expect("failed to construct trace Merkle tree")
        unimplemented!("TODO")
    }

    // POLYNOMIAL EVALUATION
    // ================================================================================================

    /// Evaluates polynomial `p` in-place over the domain of length `p.len()` in the field specified
    /// by `B` using the FFT algorithm.
    pub fn evaluate_poly(p: &mut RowMatrix<E>, twiddles: &[E::BaseField]) {
        FftInputs::fft_in_place(p, twiddles);
        FftInputs::permute(p);
    }

    // POLYNOMIAL INTERPOLATION
    // ================================================================================================

    /// Interpolates `evaluations` over a domain of length `evaluations.len()` in the field specified
    /// `B` into a polynomial in coefficient form using the FFT algorithm.
    pub fn interpolate_poly(evaluations: &mut RowMatrix<E>, inv_twiddles: &[E::BaseField]) {
        FftInputs::fft_in_place(evaluations, inv_twiddles);
        let inv_length = E::BaseField::inv((evaluations.len() as u64).into());

        // Use fftinputs shift_by on evaluations.
        FftInputs::shift_by(evaluations, inv_length);
        FftInputs::permute(evaluations);
    }

    /// Interpolates `evaluations` over a domain of length `evaluations.len()` and shifted by
    /// `domain_offset` in the field specified by `B` into a polynomial in coefficient form using
    /// the FFT algorithm.
    pub fn interpolate_poly_with_offset(
        evaluations: &mut RowMatrix<E>,
        inv_twiddles: &[E::BaseField],
        domain_offset: E::BaseField,
    ) {
        FftInputs::fft_in_place(evaluations, inv_twiddles);
        FftInputs::permute(evaluations);

        let domain_offset = E::BaseField::inv(domain_offset);
        let offset = E::BaseField::inv((evaluations.len() as u64).into());

        // Use fftinputs's shift_by_series on evaluations.
        FftInputs::shift_by_series(evaluations, offset, domain_offset);
    }
}

/// Evaluates polynomial `p` over the domain of length `p.len()` * `blowup_factor` shifted by
/// `domain_offset` in the field specified `B` using the FFT algorithm and returns the result.
pub fn evaluate_poly_with_offset<'a, E>(
    p: &RowMatrix<E>,
    twiddles: &[E::BaseField],
    domain_offset: E::BaseField,
    blowup_factor: usize,
    result: &mut RowMatrix<'a, E>,
) -> Vec<E>
where
    E: FieldElement,
{
    let domain_size = p.len() * blowup_factor;
    let g = E::BaseField::get_root_of_unity(log2(domain_size));

    let data = result.as_data_mut();

    data.chunks_mut(p.len() * p.row_width)
        .enumerate()
        .for_each(|(i, chunk)| {
            let idx = fft::permute_index(blowup_factor, i) as u64;
            let offset = g.exp(idx.into()) * domain_offset;
            let mut factor = E::BaseField::ONE;

            let chunk_len = chunk.len() / p.row_width;
            for d in 0..chunk_len {
                for i in 0..p.row_width {
                    chunk[d * p.row_width + i] = p.data[d * p.row_width + i].mul_base(factor)
                }
                factor *= offset;
            }
            let mut matrix_chunk = RowMatrix {
                data: chunk,
                row_width: p.row_width,
            };
            FftInputs::fft_in_place(&mut matrix_chunk, twiddles);
        });

    let mut matrix_result = RowMatrix {
        data,
        row_width: p.row_width,
    };

    FftInputs::permute(&mut matrix_result);
    matrix_result.data.to_vec()
}

/// Implementation of `FftInputs` for `RowMajor`.
impl<'a, B, E> FftInputs<B> for RowMatrix<'a, E>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    fn len(&self) -> usize {
        self.data.len() / self.row_width
    }

    #[inline(always)]
    fn butterfly(&mut self, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;

        for col_idx in 0..self.row_width {
            let temp = self.data[self.row_width * i + col_idx];
            self.data[self.row_width * i + col_idx] =
                temp + self.data[self.row_width * j + col_idx];
            self.data[self.row_width * j + col_idx] =
                temp - self.data[self.row_width * j + col_idx];
        }
    }

    #[inline(always)]
    fn butterfly_twiddle(&mut self, twiddle: E::BaseField, offset: usize, stride: usize) {
        let i = offset;
        let j = offset + stride;

        for col_idx in 0..self.row_width {
            let temp = self.data[self.row_width * i + col_idx];
            self.data[self.row_width * j + col_idx] =
                self.data[self.row_width * j + col_idx].mul_base(twiddle);
            self.data[self.row_width * i + col_idx] =
                temp + self.data[self.row_width * j + col_idx];
            self.data[self.row_width * j + col_idx] =
                temp - self.data[self.row_width * j + col_idx];
        }
    }

    fn swap(&mut self, i: usize, j: usize) {
        for col_idx in 0..self.row_width {
            self.data
                .swap(self.row_width * i + col_idx, self.row_width * j + col_idx);
        }
    }

    fn shift_by_series(&mut self, offset: E::BaseField, increment: E::BaseField) {
        let increment = E::from(increment);
        let mut offset = E::from(offset);
        for d in 0..self.len() {
            for i in 0..self.row_width {
                self.data[d * self.row_width + i] *= offset
            }
            offset *= increment;
        }
    }

    fn shift_by(&mut self, offset: E::BaseField) {
        let offset = E::from(offset);
        for d in self.data.iter_mut() {
            *d *= offset;
        }
    }
}
