use super::StarkDomain;
use core::iter::FusedIterator;
use core::ops::{Deref, DerefMut};
use crypto::{ElementHasher, MerkleTree};
use math::{fft, polynom, FieldElement, Matrix, RowMajorTable};
use utils::{batch_iter_mut, collections::Vec, uninit_vector};

#[derive(Debug, Clone)]
pub struct Table<E: FieldElement> {
    pub table: RowMajorTable<E>,
}

impl<E: FieldElement> Deref for Table<E> {
    type Target = RowMajorTable<E>;

    fn deref(&self) -> &Self::Target {
        &self.table
    }
}

impl<E: FieldElement> DerefMut for Table<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.table
    }
}

impl<E: FieldElement> Table<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Table] instantiated with the data from the specified columns.
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

        Self {
            table: RowMajorTable::from_columns(columns),
        }
    }

    /// Copies values of all columns at the specified row into the specified row slice.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this table.
    pub fn read_row_into(&self, row_idx: usize, row: &mut [E]) {
        for (table_value, value) in self.table.get_row(row_idx).iter().zip(row.iter_mut()) {
            *value = *table_value
        }
    }

    /// Updates a row in this table at the specified index to the provided data.
    ///
    /// # Panics
    /// Panics if `row_idx` is out of bounds for this table.
    pub fn update_row(&mut self, row_idx: usize, row: &[E]) {
        for (table_value, value) in self.table.get_row_mut(row_idx).iter_mut().zip(row) {
            *table_value = *value
        }
    }

    /// Returns the columns of this matrix as a list of vectors.
    pub fn into_columns(&self) -> Vec<Vec<E>> {
        (0..self.num_cols()).map(|n| self.into_column(n)).collect()
    }

    /// Returns the column at the specified index.
    pub fn into_column(&self, index: usize) -> Vec<E> {
        self.data()
            .iter()
            .copied()
            .skip(index)
            .step_by(self.num_cols())
            .collect()
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
        // TODO: get ride of cloning by introducing another version of fft::interpolate_poly()
        let mut result = self.clone();
        fft::matrix::interpolate_poly(&mut result.table, &inv_twiddles);
        result
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
        fft::matrix::interpolate_poly(&mut self.table, &inv_twiddles);
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
        let table = fft::matrix::evaluate_poly_with_offset(
            &self.table,
            domain.trace_twiddles(),
            domain.offset(),
            domain.trace_to_lde_blowup(),
        );
        Self { table }
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
        // allocate vector to store row hashes
        let mut row_hashes = unsafe { uninit_vector::<H::Digest>(self.table.num_rows()) };

        // iterate though matrix rows, hashing each row; the hashing is done by first copying a
        // row into row_buf to avoid heap allocations, and then by applying the hash function to
        // the buffer.
        batch_iter_mut!(
            &mut row_hashes,
            128, // min batch size
            |batch: &mut [H::Digest], batch_offset: usize| {
                let mut row_buf = vec![E::ZERO; self.table.num_cols()];
                for (i, row_hash) in batch.iter_mut().enumerate() {
                    self.read_row_into(i + batch_offset, &mut row_buf);
                    *row_hash = H::hash_elements(&row_buf);
                }
            }
        );

        // build Merkle tree out of hashed rows
        MerkleTree::new(row_hashes).expect("failed to construct trace Merkle tree")
    }
}

// COLUMN ITERATOR
// ================================================================================================

pub struct ColIterator<'a, E: FieldElement> {
    matrix: &'a Table<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> ColIterator<'a, E> {
    pub fn new(matrix: &'a Table<E>) -> Self {
        Self { matrix, cursor: 0 }
    }
}

impl<'a, E: FieldElement + 'a> Iterator for ColIterator<'a, E> {
    type Item = Vec<E>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.matrix.num_cols() - self.cursor {
            0 => None,
            _ => {
                let column = self.matrix.into_column(self.cursor);
                self.cursor += 1;
                Some(column)
            }
        }
    }
}

impl<'a, E: FieldElement + 'a> ExactSizeIterator for ColIterator<'a, E> {
    fn len(&self) -> usize {
        self.matrix.num_cols()
    }
}

impl<'a, E: FieldElement> FusedIterator for ColIterator<'a, E> {}

// MULTI-MATRIX COLUMN ITERATOR
// ================================================================================================

pub struct MultiColIterator<'a, E: FieldElement> {
    matrixes: &'a [Table<E>],
    m_cursor: usize,
    c_cursor: usize,
}

impl<'a, E: FieldElement> MultiColIterator<'a, E> {
    pub fn new(matrixes: &'a [Table<E>]) -> Self {
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

impl<'a, E: FieldElement> Iterator for MultiColIterator<'a, E> {
    type Item = Vec<E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.matrixes.is_empty() {
            return None;
        }
        let matrix = &self.matrixes[self.m_cursor];
        match matrix.num_cols() - self.c_cursor {
            0 => None,
            _ => {
                let column = matrix.into_column(self.c_cursor);
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

impl<'a, E: FieldElement> ExactSizeIterator for MultiColIterator<'a, E> {
    fn len(&self) -> usize {
        self.matrixes.iter().fold(0, |s, m| s + m.num_cols())
    }
}

impl<'a, E: FieldElement> FusedIterator for MultiColIterator<'a, E> {}
