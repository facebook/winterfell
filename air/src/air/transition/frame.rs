// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{super::Air, FieldElement};
use crate::Table;
use utils::TableReader;

/// A set of execution trace rows required for evaluation of transition constraints.
/// It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
pub trait EvaluationFrame<E: FieldElement> {
    /// Creates an empty frame
    fn new<A: Air>(air: &A) -> Self;

    /// Creates a new frame instantiated from the provided row-major table
    fn from_table(table: Table<E>) -> Self;

    /// Convert frame to a row-major table
    fn to_table(&self) -> Table<E>;

    /// Reads selected trace rows from the supplied data into the frame
    fn read_from<R: TableReader<E>>(&mut self, data: R, step: usize, offset: usize, blowup: usize);

    /// Returns the specified frame row
    fn row<'a>(&'a self, index: usize) -> &'a [E];

    /// Returns the number of frame rows
    fn num_rows() -> usize {
        Self::offsets().len()
    }

    /// Returns the offsets that make up a frame
    fn offsets() -> &'static [usize];
}

/// Contains rows of the execution trace
#[derive(Debug, Clone)]
pub struct DefaultEvaluationFrame<E: FieldElement> {
    table: Table<E>, // row-major indexing
}

// DEFAULT EVALUATION FRAME
// ================================================================================================

impl<E: FieldElement> EvaluationFrame<E> for DefaultEvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    fn new<A: Air>(air: &A) -> Self {
        let num_cols = air.trace_layout().main_trace_width();
        let num_rows = Self::num_rows();
        DefaultEvaluationFrame {
            table: Table::new(num_rows, num_cols),
        }
    }

    fn from_table(table: Table<E>) -> Self {
        Self { table }
    }

    // ROW MUTATORS
    // --------------------------------------------------------------------------------------------

    fn read_from<R: TableReader<E>>(&mut self, data: R, step: usize, offset: usize, blowup: usize) {
        let trace_len = data.num_rows();
        for (row, row_idx) in self.table.rows_mut().zip(Self::offsets().into_iter()) {
            for col_idx in 0..data.num_cols() {
                row[col_idx + offset] = data.get(col_idx, (step + row_idx * blowup) % trace_len);
            }
        }
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    fn row<'a>(&'a self, row_idx: usize) -> &'a [E] {
        &self.table.get_row(row_idx)
    }

    fn to_table(&self) -> Table<E> {
        self.table.clone()
    }

    fn offsets() -> &'static [usize] {
        &[0, 1]
    }
}

impl<E: FieldElement> DefaultEvaluationFrame<E> {
    pub fn current<'a>(&'a self) -> &'a [E] {
        &self.table.get_row(0)
    }
    pub fn next<'a>(&'a self) -> &'a [E] {
        &self.table.get_row(1)
    }
}
