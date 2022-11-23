// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{super::Air, FieldElement, Vec};
use utils::TableReader;

// EVALUATION FRAME TRAIT
// ================================================================================================
/// Defines a frame for evaluation of transition constraints.
///
/// It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
pub trait EvaluationFrame<E: FieldElement> {
    /// Creates an empty frame.
    fn new<A: Air>(air: &A) -> Self;

    /// Reads selected trace rows from the supplied data into the frame.
    fn read_from<R: TableReader<E>>(&mut self, data: R, step: usize, offset: usize, blowup: usize);

    /// Creates a new frame instantiated from the provided row-major list of 2 consecutive rows.
    fn from_table(table: &[Vec<E>; 2]) -> Self;

    /// Convert frame to a row-major list of 2 consecutive rows.
    fn to_table(&self) -> [Vec<E>; 2];

    /// Returns the current frame row.
    fn current(&self) -> &[E];

    /// Returns the next frame row.
    fn next(&self) -> &[E];
}

/// Default implementation of the Evaluation Frame trait, which contains two consecutive rows of
/// the execution trace.
#[derive(Debug, Clone)]
pub struct DefaultEvaluationFrame<E: FieldElement> {
    current: Vec<E>,
    next: Vec<E>,
}

impl<E: FieldElement> EvaluationFrame<E> for DefaultEvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new evaluation frame instantiated from an instance of AIR.
    fn new<A: Air>(air: &A) -> Self {
        let num_cols = air.trace_layout().main_trace_width();
        DefaultEvaluationFrame {
            current: E::zeroed_vector(num_cols),
            next: E::zeroed_vector(num_cols),
        }
    }

    /// Reads the values of current and next row from data.
    fn read_from<R: TableReader<E>>(&mut self, data: R, step: usize, offset: usize, blowup: usize) {
        let trace_len = data.num_rows();
        for col_idx in 0..data.num_cols() {
            self.current[col_idx + offset] = data.get(col_idx, step % trace_len);
            self.next[col_idx + offset] = data.get(col_idx, (step + blowup) % trace_len);
        }
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the current row.
    #[inline(always)]
    fn current(&self) -> &[E] {
        &self.current
    }

    /// Returns a reference to the next row.
    #[inline(always)]
    fn next(&self) -> &[E] {
        &self.next
    }

    /// Generates current and next row from the provided row-major list of 2 consecutive rows.
    fn from_table(table: &[Vec<E>; 2]) -> Self {
        Self {
            current: table
                .first()
                .expect("Failed to fetch the first element")
                .to_vec(),
            next: table
                .last()
                .expect("Failed to fetch the last element")
                .to_vec(),
        }
    }

    /// Convert current and next row to a row-major list of 2 consecutive rows.
    fn to_table(&self) -> [Vec<E>; 2] {
        [self.current().to_vec(), self.next().to_vec()]
    }
}

impl<E: FieldElement> DefaultEvaluationFrame<E> {
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
