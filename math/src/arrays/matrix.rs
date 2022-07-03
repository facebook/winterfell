use crate::FieldElement;
use core::{iter::FusedIterator, slice};
use std::marker::PhantomData;
use utils::collections::Vec;

// CONSTANTS
// ================================================================================================

#[allow(dead_code)]
const MAX_ROWS: usize = 255;
#[allow(dead_code)]
const MAX_COLS: usize = 255;

// MATRIX
// ================================================================================================

/// A matrix imposes the following restrictions on its content:
/// - A matrix must consist of at least 1 column and at least 2 rows.
/// - All columns must be of the same length.
/// - Number of rows must be a power of two.
pub trait Matrix<E: FieldElement>: Sized {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an empty Matrix of size zero
    fn new() -> Self;

    /// Returns a new uninitialized Matrix of dimension (num_rows, num_cols)
    fn uninit(num_rows: usize, num_cols: usize) -> Self;

    /// Returns a new Matrix with a reference to the data at chunk
    // TODO: Use associated type to specify reference table?
    fn as_ref_table<'a>(chunk: &'a mut [E], row_width: usize) -> RowMajorRefTable<'a, E> {
        RowMajorRefTable {
            data: chunk,
            row_width,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of rows in this matrix.
    fn num_rows(&self) -> usize;

    /// Returns number of columns in this matrix.
    fn num_cols(&self) -> usize;

    /// Returns the cell located at the specified column and row indexes in this matrix.
    fn get(&self, col_idx: usize, row_idx: usize) -> E;

    /// Set the cell in this matrix at the specified column and row indexes to the provided value.
    fn set(&mut self, col_idx: usize, row_idx: usize, value: E);

    /// Returns a reference to a row at the specified index.
    fn get_row<'a>(&'a self, index: usize) -> &'a [E];

    /// Returns a mutable reference to the row at the specified index.
    fn get_row_mut<'a>(&'a mut self, index: usize) -> &'a mut [E];

    /// Returns a reference to a column at the specified index.
    fn get_column<'a>(&'a self, index: usize) -> &'a [E];

    /// Returns a mutable reference to the column at the specified index.
    fn get_column_mut<'a>(&'a mut self, index: usize) -> &'a mut [E];

    /// Returns a contiguous reference to the underlying data
    fn data<'a>(&'a self) -> &'a [E];

    /// Returns a mutable contiguous reference to the underlying data
    fn data_mut<'a>(&'a mut self) -> &'a mut [E];

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the rows of this matrix.
    fn rows(&self) -> RowIterator<E, Self> {
        RowIterator::new(self)
    }

    /// Returns a mutable iterator over the rows of this matrix.
    fn rows_mut(&mut self) -> RowIteratorMut<E, Self> {
        RowIteratorMut::new(self)
    }

    /// Returns an iterator over the columns of this matrix.
    fn columns(&self) -> ColIterator<E, Self> {
        ColIterator::new(self)
    }

    /// Returns a mutable iterator over the columns of this matrix.
    fn columns_mut(&mut self) -> ColIteratorMut<E, Self> {
        ColIteratorMut::new(self)
    }
}

// ROW MAJOR TABLE
// ================================================================================================

/// A two-dimensional table of field elements arranged in row-major order.
///
/// This struct is used primarily to hold queried values of execution trace segments and constraint
/// evaluations. In such cases, each row in the table corresponds to a single query, and each
/// column corresponds to a trace segment column or a constraint evaluation column.
#[derive(Debug, Clone)]
pub struct RowMajorTable<E: FieldElement> {
    data: Vec<E>,
    row_width: usize,
}

impl<E: FieldElement> RowMajorTable<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Matrix] instantiated with the data from the specified rows.
    pub fn from_rows(rows: Vec<Vec<E>>) -> Self {
        let row_width = rows[0].len();
        Self {
            data: rows.into_iter().flatten().collect::<Vec<_>>(),
            row_width,
        }
    }

    /// Returns a new [Matrix] instantiated with the data from the specified columns.
    pub fn from_columns(cols: Vec<Vec<E>>) -> Self {
        let row_width = cols.len();
        Self {
            data: transpose(cols).into_iter().flatten().collect::<Vec<_>>(),
            row_width,
        }
    }
}

impl<E: FieldElement> Matrix<E> for RowMajorTable<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    fn new() -> Self {
        Self {
            data: vec![],
            row_width: 0,
        }
    }

    fn uninit(num_rows: usize, num_cols: usize) -> Self {
        Self {
            data: E::zeroed_vector(num_rows * num_cols),
            row_width: num_cols,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    fn num_rows(&self) -> usize {
        self.data.len() / self.row_width
    }

    fn num_cols(&self) -> usize {
        self.row_width
    }

    fn get(&self, col_idx: usize, row_idx: usize) -> E {
        self.data[row_idx * self.row_width + col_idx]
    }

    fn set(&mut self, col_idx: usize, row_idx: usize, value: E) {
        self.data[row_idx * self.row_width + col_idx] = value
    }

    fn get_row(&self, row_idx: usize) -> &[E] {
        let row_offset = row_idx * self.row_width;
        &self.data[row_offset..row_offset + self.row_width]
    }

    fn get_column(&self, _col_idx: usize) -> &[E] {
        unimplemented!()
    }

    fn get_row_mut(&mut self, row_idx: usize) -> &mut [E] {
        let row_offset = row_idx * self.row_width;
        &mut self.data[row_offset..row_offset + self.row_width]
    }

    fn get_column_mut(&mut self, _col_idx: usize) -> &mut [E] {
        unimplemented!()
    }

    fn data(&self) -> &[E] {
        &self.data[..]
    }
    fn data_mut(&mut self) -> &mut [E] {
        &mut self.data[..]
    }
}

// ROW MAJOR REFERENCE TABLE
// ================================================================================================

pub struct RowMajorRefTable<'a, E: FieldElement> {
    data: &'a mut [E],
    row_width: usize,
}

impl<'a, E: FieldElement> RowMajorRefTable<'a, E> {
    pub fn from_row_data(data: &'a mut [E], row_width: usize) -> Self {
        Self { data, row_width }
    }
}

impl<'a, E: FieldElement> Matrix<E> for RowMajorRefTable<'a, E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    fn new() -> Self {
        unimplemented!()
    }

    fn uninit(_num_rows: usize, _num_cols: usize) -> Self {
        unimplemented!()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    fn num_rows(&self) -> usize {
        self.data.len() / self.row_width
    }

    fn num_cols(&self) -> usize {
        self.row_width
    }

    fn get(&self, col_idx: usize, row_idx: usize) -> E {
        self.data[row_idx * self.row_width + col_idx]
    }

    fn set(&mut self, col_idx: usize, row_idx: usize, value: E) {
        self.data[row_idx * self.row_width + col_idx] = value
    }

    fn get_row(&self, row_idx: usize) -> &[E] {
        let row_offset = row_idx * self.row_width;
        &self.data[row_offset..row_offset + self.row_width]
    }

    fn get_column(&self, _col_idx: usize) -> &[E] {
        unimplemented!()
    }

    fn get_row_mut(&mut self, row_idx: usize) -> &mut [E] {
        let row_offset = row_idx * self.row_width;
        &mut self.data[row_offset..row_offset + self.row_width]
    }

    fn get_column_mut(&mut self, _col_idx: usize) -> &mut [E] {
        unimplemented!()
    }

    fn data(&self) -> &[E] {
        unimplemented!()
    }
    fn data_mut(&mut self) -> &mut [E] {
        unimplemented!()
    }
}

// COLUMN MAJOR TABLE
// ================================================================================================

/// A two-dimensional table of field elements arranged in column-major order.
///
/// This struct is used as a backing type for many objects manipulated by the prover. The table
/// itself does not assign any contextual meaning to the values stored in it. For example, columns
/// may contain evaluations of polynomials, or polynomial coefficients, or really anything else.
#[derive(Debug, Clone)]
pub struct ColumnMajorTable<E: FieldElement> {
    columns: Vec<Vec<E>>,
}

impl<E: FieldElement> Matrix<E> for ColumnMajorTable<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    fn new() -> Self {
        Self { columns: vec![] }
    }

    fn uninit(_num_rows: usize, _num_cols: usize) -> Self {
        unimplemented!()
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    fn num_cols(&self) -> usize {
        self.columns.len()
    }

    fn num_rows(&self) -> usize {
        self.columns[0].len()
    }

    fn get(&self, _col_idx: usize, row_idx: usize) -> E {
        self.columns[row_idx][row_idx]
    }

    fn set(&mut self, col_idx: usize, row_idx: usize, value: E) {
        self.columns[col_idx][row_idx] = value;
    }

    fn get_row(&self, _row_idx: usize) -> &[E] {
        unimplemented!()
    }

    fn get_column(&self, col_idx: usize) -> &[E] {
        &self.columns[col_idx]
    }

    fn get_column_mut(&mut self, col_idx: usize) -> &mut [E] {
        &mut self.columns[col_idx]
    }

    fn get_row_mut(&mut self, _row_idx: usize) -> &mut [E] {
        unimplemented!()
    }

    fn data(&self) -> &[E] {
        unimplemented!()
    }

    fn data_mut(&mut self) -> &mut [E] {
        unimplemented!()
    }
}

// ROW ITERATOR
// ================================================================================================

pub struct RowIterator<'a, E: FieldElement, M: Matrix<E>> {
    table: &'a M,
    cursor: usize,
    phantom: PhantomData<&'a E>,
}

impl<'a, E: FieldElement, M: Matrix<E>> RowIterator<'a, E, M> {
    pub fn new(table: &'a M) -> Self {
        Self {
            table,
            cursor: 0,
            phantom: PhantomData,
        }
    }
}

impl<'a, E: FieldElement + 'a, M: Matrix<E>> Iterator for RowIterator<'a, E, M> {
    type Item = &'a [E];

    fn next(&mut self) -> Option<Self::Item> {
        match self.table.num_rows() - self.cursor {
            0 => None,
            _ => {
                let row = self.table.get_row(self.cursor);
                self.cursor += 1;
                Some(row)
            }
        }
    }
}

impl<'a, E: FieldElement + 'a, M: Matrix<E>> ExactSizeIterator for RowIterator<'a, E, M> {
    fn len(&self) -> usize {
        self.table.num_rows()
    }
}

impl<'a, E: FieldElement + 'a, M: Matrix<E>> FusedIterator for RowIterator<'a, E, M> {}

// MUTABLE ROW ITERATOR
// ================================================================================================

pub struct RowIteratorMut<'a, E: FieldElement, M: Matrix<E>> {
    table: &'a mut M,
    cursor: usize,
    phantom: PhantomData<&'a E>,
}

impl<'a, E: FieldElement, M: Matrix<E>> RowIteratorMut<'a, E, M> {
    pub fn new(table: &'a mut M) -> Self {
        Self {
            table,
            cursor: 0,
            phantom: PhantomData,
        }
    }
}

impl<'a, E: FieldElement + 'a, M: Matrix<E>> Iterator for RowIteratorMut<'a, E, M> {
    type Item = &'a mut [E];

    fn next(&mut self) -> Option<Self::Item> {
        match self.table.num_rows() - self.cursor {
            0 => None,
            _ => {
                let row = self.table.get_row_mut(self.cursor);
                self.cursor += 1;

                // this is needed to get around mutable iterator lifetime issues; this is safe
                // because the iterator can never yield a reference to the same column twice
                let p = row.as_ptr();
                let len = row.len();
                Some(unsafe { slice::from_raw_parts_mut(p as *mut E, len) })
            }
        }
    }
}

// COLUMN ITERATOR
// ================================================================================================

pub struct ColIterator<'a, E: FieldElement, M: Matrix<E>> {
    matrix: &'a M,
    cursor: usize,
    phantom: PhantomData<&'a E>,
}

impl<'a, E: FieldElement, M: Matrix<E>> ColIterator<'a, E, M> {
    pub fn new(matrix: &'a M) -> Self {
        Self {
            matrix,
            cursor: 0,
            phantom: PhantomData,
        }
    }
}

impl<'a, E: FieldElement + 'a, M: Matrix<E>> Iterator for ColIterator<'a, E, M> {
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

impl<'a, E: FieldElement + 'a, M: Matrix<E>> ExactSizeIterator for ColIterator<'a, E, M> {
    fn len(&self) -> usize {
        self.matrix.num_cols()
    }
}

impl<'a, E: FieldElement + 'a, M: Matrix<E>> FusedIterator for ColIterator<'a, E, M> {}

// MUTABLE COLUMN ITERATOR
// ================================================================================================

pub struct ColIteratorMut<'a, E: FieldElement, M: Matrix<E>> {
    matrix: &'a mut M,
    cursor: usize,
    phantom: PhantomData<&'a E>,
}

impl<'a, E: FieldElement, M: Matrix<E>> ColIteratorMut<'a, E, M> {
    pub fn new(matrix: &'a mut M) -> Self {
        Self {
            matrix,
            cursor: 0,
            phantom: PhantomData,
        }
    }
}

impl<'a, E: FieldElement, M: Matrix<E>> Iterator for ColIteratorMut<'a, E, M> {
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

impl<'a, E: FieldElement, M: Matrix<E>> ExactSizeIterator for ColIteratorMut<'a, E, M> {
    fn len(&self) -> usize {
        self.matrix.num_cols()
    }
}

impl<'a, E: FieldElement, M: Matrix<E>> FusedIterator for ColIteratorMut<'a, E, M> {}

// MULTI-MATRIX COLUMN ITERATOR
// ================================================================================================

pub struct MultiColIterator<'a, E: FieldElement, M: Matrix<E>> {
    matrixes: &'a [M],
    m_cursor: usize,
    c_cursor: usize,
    phantom: PhantomData<&'a E>,
}

impl<'a, E: FieldElement, M: Matrix<E>> MultiColIterator<'a, E, M> {
    pub fn new(matrixes: &'a [M]) -> Self {
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
            phantom: PhantomData,
        }
    }
}

impl<'a, E: FieldElement, M: Matrix<E>> Iterator for MultiColIterator<'a, E, M> {
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

impl<'a, E: FieldElement, M: Matrix<E>> ExactSizeIterator for MultiColIterator<'a, E, M> {
    fn len(&self) -> usize {
        self.matrixes.iter().fold(0, |s, m| s + m.num_cols())
    }
}

impl<'a, E: FieldElement, M: Matrix<E>> FusedIterator for MultiColIterator<'a, E, M> {}

// HELPER FUNCTIONS
// ================================================================================================

fn transpose<E: FieldElement>(v: Vec<Vec<E>>) -> Vec<Vec<E>> {
    (0..v[0].len())
        .map(|i| v.iter().map(|inner| inner[i].clone()).collect::<Vec<E>>())
        .collect()
}
