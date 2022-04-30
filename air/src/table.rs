use core::{iter::FusedIterator, slice};
use math::FieldElement;
use utils::{collections::Vec, DeserializationError, SliceReader};

// CONSTANTS
// ================================================================================================

const MAX_ROWS: usize = 255;
const MAX_COLS: usize = 255;

// TABLE
// ================================================================================================

/// A two-dimensional table of field elements arranged in row-major order.
///
/// This struct is used primarily to hold queried values of execution trace segments and constraint
/// evaluations. In such cases, each row in the table corresponds to a single query, and each
/// column corresponds to a trace segment column or a constraint evaluation column.
#[derive(Debug, Clone)]
pub struct Table<E: FieldElement> {
    data: Vec<E>,
    row_width: usize,
}

impl<E: FieldElement> Table<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new [Table] instantiated with data from the provided bytes.
    ///
    /// # Panics
    /// Panics if:
    /// * Specified number of rows is 0 or greater than 255.
    /// * Specified number of columns is 0 or greater than 255.
    /// * Provided bytes do not encode valid field elements required to fill the table.
    pub fn from_bytes(
        bytes: &[u8],
        num_rows: usize,
        num_cols: usize,
    ) -> Result<Self, DeserializationError> {
        assert!(num_rows > 0, "number of rows must be greater than 0");
        assert!(
            num_rows < MAX_ROWS,
            "number of rows cannot exceed {}, but was {}",
            MAX_ROWS,
            num_rows
        );
        assert!(num_cols > 0, "number of columns must be greater than 0");
        assert!(
            num_cols < MAX_ROWS,
            "number of columns cannot exceed {}, but was {}",
            MAX_COLS,
            num_cols
        );

        let mut reader = SliceReader::new(bytes);
        let num_elements = num_rows * num_cols;
        Ok(Self {
            data: E::read_batch_from(&mut reader, num_elements)?,
            row_width: num_cols,
        })
    }

    pub fn from_rows(rows: Vec<Vec<E>>) -> Self {
        let row_width = rows[0].len();
        Self {
            data: rows.into_iter().flatten().collect(),
            row_width,
        }
    }

    pub fn new(num_rows: usize, num_cols: usize) -> Self {
        Self {
            data: E::zeroed_vector(num_rows * num_cols),
            row_width: num_cols,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of rows in this table.
    pub fn num_rows(&self) -> usize {
        self.data.len() / self.row_width
    }

    /// Returns number of columns in this table.
    pub fn num_columns(&self) -> usize {
        self.row_width
    }

    /// Returns a reference to a row at the specified index.
    pub fn get_row(&self, row_idx: usize) -> &[E] {
        let row_offset = row_idx * self.row_width;
        &self.data[row_offset..row_offset + self.row_width]
    }

    /// Returns a mutable reference to the row at the specified index.
    pub fn get_row_mut(&mut self, row_idx: usize) -> &mut [E] {
        let row_offset = row_idx * self.row_width;
        &mut self.data[row_offset..row_offset + self.row_width]
    }

    // ITERATION
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the columns of this matrix.
    pub fn rows(&self) -> RowIter<E> {
        RowIter::new(self)
    }

    /// Returns a mutable iterator over the columns of this matrix.
    pub fn rows_mut(&mut self) -> RowIterMut<E> {
        RowIterMut::new(self)
    }

    // TABLE PROCESSING
    // --------------------------------------------------------------------------------------------

    /// Combines multiple tables together into a single table by stacking tables column-wise (e.g.
    /// the number of rows remains the same but the number of columns changes).
    ///
    /// Currently, this method does not support inputs containing more than one table.
    ///
    /// # Panics
    /// Panics if the list of tables is empty.
    pub fn merge(mut tables: Vec<Table<E>>) -> Table<E> {
        assert!(!tables.is_empty(), "cannot merge an empty set of tables");
        if tables.len() == 1 {
            tables.remove(0)
        } else {
            unimplemented!("merging of multiple tables is not yet implemented")
        }
    }
}

// COLUMN ITERATOR
// ================================================================================================

pub struct RowIter<'a, E: FieldElement> {
    table: &'a Table<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> RowIter<'a, E> {
    pub fn new(table: &'a Table<E>) -> Self {
        Self { table, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for RowIter<'a, E> {
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

impl<'a, E: FieldElement> ExactSizeIterator for RowIter<'a, E> {
    fn len(&self) -> usize {
        self.table.num_rows()
    }
}

impl<'a, E: FieldElement> FusedIterator for RowIter<'a, E> {}

// MUTABLE COLUMN ITERATOR
// ================================================================================================

pub struct RowIterMut<'a, E: FieldElement> {
    table: &'a mut Table<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> RowIterMut<'a, E> {
    pub fn new(table: &'a mut Table<E>) -> Self {
        Self { table, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for RowIterMut<'a, E> {
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

impl<'a, E: FieldElement> ExactSizeIterator for RowIterMut<'a, E> {
    fn len(&self) -> usize {
        self.table.num_rows()
    }
}

impl<'a, E: FieldElement> FusedIterator for RowIterMut<'a, E> {}
