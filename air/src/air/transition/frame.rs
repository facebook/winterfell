// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use super::FieldElement;

// EVALUATION FRAME
// ================================================================================================

/// A set of execution trace rows required for evaluation of transition constraints.
///
/// In the current implementation, an evaluation frame always contains two consecutive rows of the
/// execution trace. It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
#[derive(Debug, Clone)]
pub struct EvaluationFrame<E: FieldElement> {
    current: Vec<E>,
    next: Vec<E>,
}

impl<E: FieldElement> EvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new evaluation frame instantiated with the specified number of columns.
    ///
    /// # Panics
    /// Panics if `num_columns` is zero.
    pub fn new(num_columns: usize) -> Self {
        assert!(num_columns > 0, "number of columns must be greater than zero");
        EvaluationFrame {
            current: vec![E::ZERO; num_columns],
            next: vec![E::ZERO; num_columns],
        }
    }

    /// Returns a new evaluation frame instantiated from the provided rows.
    ///
    /// # Panics
    /// Panics if:
    /// * Lengths of the provided rows are zero.
    /// * Lengths of the provided rows are not the same.
    pub fn from_rows(current: Vec<E>, next: Vec<E>) -> Self {
        assert!(!current.is_empty(), "a row must contain at least one value");
        assert_eq!(current.len(), next.len(), "number of values in the rows must be the same");
        Self { current, next }
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the current row.
    #[inline(always)]
    pub fn current(&self) -> &[E] {
        &self.current
    }

    /// Returns a reference to the next row.
    #[inline(always)]
    pub fn next(&self) -> &[E] {
        &self.next
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the current row.
    #[inline(always)]
    pub fn current_mut(&mut self) -> &mut [E] {
        &mut self.current
    }

    /// Returns a mutable reference to the next row.
    #[inline(always)]
    pub fn next_mut(&mut self) -> &mut [E] {
        &mut self.next
    }
}
