use super::{DeserializationError, SliceReader};
use core::iter::FusedIterator;
use math::FieldElement;

#[derive(Debug, Clone)]
pub struct Table<E: FieldElement> {
    data: Vec<E>,
    row_width: usize,
}

impl<E: FieldElement> Table<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    pub fn new(data: Vec<E>, row_width: usize) -> Self {
        assert!(data.len() % row_width == 0, "");
        Self { data, row_width }
    }

    pub fn from_bytes(
        bytes: &[u8],
        num_rows: usize,
        num_cols: usize,
    ) -> Result<Self, DeserializationError> {
        let mut reader = SliceReader::new(bytes);
        let num_elements = num_rows * num_cols;
        let data = E::read_batch_from(&mut reader, num_elements)?;
        Ok(Self {
            data,
            row_width: num_cols,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    pub fn get_row(&self, row_idx: usize) -> &[E] {
        let row_offset = row_idx * self.row_width;
        &self.data[row_offset..row_offset + self.row_width]
    }

    pub fn num_rows(&self) -> usize {
        self.data.len() / self.row_width
    }

    pub fn num_columns(&self) -> usize {
        self.row_width
    }

    pub fn rows(&self) -> RowIterator<E> {
        RowIterator::new(self)
    }
}

// COLUMN ITERATOR
// ================================================================================================

pub struct RowIterator<'a, E: FieldElement> {
    table: &'a Table<E>,
    cursor: usize,
}

impl<'a, E: FieldElement> RowIterator<'a, E> {
    pub fn new(table: &'a Table<E>) -> Self {
        Self { table, cursor: 0 }
    }
}

impl<'a, E: FieldElement> Iterator for RowIterator<'a, E> {
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

impl<'a, E: FieldElement> ExactSizeIterator for RowIterator<'a, E> {
    fn len(&self) -> usize {
        self.table.num_rows()
    }
}

impl<'a, E: FieldElement> FusedIterator for RowIterator<'a, E> {}
