// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{super::Air, FieldElement, Vec};
use utils::iterators::StreamingIterator;

/// A set of execution trace rows required for evaluation of transition constraints.
/// It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
pub trait EvaluationFrame<E: FieldElement> {
    /// Creates an empty frame
    fn new<A: Air>(air: &A) -> Self;

    /// Creates an frame instantiated from the provided rows
    fn from_rows(rows: Vec<Vec<E>>) -> Self;

    /// Fills the frame using the provided column iterator
    fn read_from<'a, I: StreamingIterator>(&mut self, columns: I, step: usize);

    /// Returns the specified row
    fn row<'a>(&'a self, index: usize) -> &'a [E];

    /// Returns the number of rows
    fn row_count(&self) -> usize;
}

/// Contains rows of the execution trace
#[derive(Debug, Clone)]
pub struct DefaultEvaluationFrame<E: FieldElement> {
    data: Vec<Vec<E>>, // row-major indexing
}

// WINDOWED EVALUATION FRAME
// ================================================================================================

impl<E: FieldElement> DefaultEvaluationFrame<E> {}

impl<E: FieldElement> EvaluationFrame<E> for DefaultEvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    fn new<A: Air>(air: &A) -> Self {
        let num_columns = air.trace_layout().main_trace_width();
        let num_rows = 2; // TODO: Specify in Air context
        DefaultEvaluationFrame {
            data: vec![E::zeroed_vector(num_columns); num_rows],
        }
    }

    fn from_rows(rows: Vec<Vec<E>>) -> Self {
        Self { data: rows }
    }

    // ROW MUTATORS
    // --------------------------------------------------------------------------------------------

    fn read_from<'a, I: StreamingIterator>(&mut self, mut columns: I, step: usize) {
        // TODO
        //loop {
        //    match columns.next() {
        //        Some(col) => {
        //            for (i, row) in self.data.iter_mut().enumerate() {
        //                row[j] = col[i];
        //            }
        //        }
        //        None => break,
        //    }
        //}
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    fn row<'a>(&'a self, index: usize) -> &'a [E] {
        &self.data[index]
    }

    fn row_count(&self) -> usize {
        self.data.len()
    }
}
