// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{FieldElement, Vec};

/// A set of execution trace rows required for evaluation of transition constraints.
/// It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
pub trait EvaluationFrame<E: FieldElement> {
    type Chunk<'a>
    where
        Self: 'a;

    fn new(width: usize) -> Self;
    fn from_rows(current: Vec<E>, next: Vec<E>) -> Self;
    fn read_segment_into(&mut self, step: usize, segment: &Vec<Vec<E>>);
    fn current<'a>(&'a self) -> Self::Chunk<'a>;
    fn next<'a>(&'a self) -> Self::Chunk<'a>;
}

/// Contains two consecutive (multi)row chunks of the execution trace.
#[derive(Debug, Clone)]
pub struct ChunkedEvaluationFrame<E: FieldElement> {
    data: Vec<Vec<E>>, // row major indexing
    window_size: usize,
}

/// Contains two consecutive single rows of the execution trace.
#[derive(Debug, Clone)]
pub struct RowEvaluationFrame<E: FieldElement> {
    current: Vec<E>,
    next: Vec<E>,
}

// WINDOWED EVALUATION FRAME
// ================================================================================================

impl<E: FieldElement> ChunkedEvaluationFrame<E> {}

impl<E: FieldElement> EvaluationFrame<E> for ChunkedEvaluationFrame<E> {
    type Chunk<'a>
    where
        Self: 'a,
    = &'a [Vec<E>];

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    fn new(num_columns: usize) -> Self {
        // TODO: Move constructor outside of trait definition?
        assert!(
            num_columns > 0,
            "number of columns must be greater than zero"
        );
        ChunkedEvaluationFrame {
            data: vec![],
            window_size: 0,
        }
    }

    fn from_rows(_current: Vec<E>, _next: Vec<E>) -> Self {
        // TODO: See above comment for ChunkedEvaluationFrame::new
        Self {
            data: vec![],
            window_size: 0,
        }
    }

    // ROW MUTATORS
    // --------------------------------------------------------------------------------------------

    fn read_segment_into(&mut self, step: usize, segment: &Vec<Vec<E>>) {
        // TODO
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the current chunk of rows.
    #[inline(always)]
    fn current<'a>(&'a self) -> Self::Chunk<'a> {
        &self.data[0..self.window_size]
    }

    /// Returns a reference to the next chunk of rows.
    #[inline(always)]
    fn next<'a>(&'a self) -> Self::Chunk<'a> {
        &self.data[self.window_size..(2 * self.window_size)]
    }
}

// CONSECUTIVE ROW EVALUATION FRAME
// ================================================================================================

impl<E: FieldElement> RowEvaluationFrame<E> {}

impl<E: FieldElement> EvaluationFrame<E> for RowEvaluationFrame<E> {
    type Chunk<'a>
    where
        Self: 'a,
    = &'a [E];

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new evaluation frame instantiated with the specified number of columns.
    ///
    /// # Panics
    /// Panics if `num_columns` is zero.
    fn new(num_columns: usize) -> Self {
        assert!(
            num_columns > 0,
            "number of columns must be greater than zero"
        );
        RowEvaluationFrame {
            current: E::zeroed_vector(num_columns),
            next: E::zeroed_vector(num_columns),
        }
    }

    /// Returns a new evaluation frame instantiated from the provided rows.
    ///
    /// # Panics
    /// Panics if:
    /// * Lengths of the provided rows are zero.
    /// * Lengths of the provided rows are not the same.
    fn from_rows(current: Vec<E>, next: Vec<E>) -> Self {
        assert!(!current.is_empty(), "a row must contain at least one value");
        assert_eq!(
            current.len(),
            next.len(),
            "number of values in the rows must be the same"
        );
        Self { current, next }
    }

    // ROW MUTATORS
    // --------------------------------------------------------------------------------------------

    fn read_segment_into<'t>(&'t mut self, _step: usize, _segment: &'t Vec<Vec<E>>) {
        // TODO
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the current row.
    #[inline(always)]
    fn current<'a>(&'a self) -> Self::Chunk<'a> {
        &self.current
    }

    /// Returns a reference to the next row.
    #[inline(always)]
    fn next<'a>(&'a self) -> Self::Chunk<'a> {
        &self.next
    }
}
