// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::ops::Range;

use winterfell::{
    math::{FieldElement, StarkField},
    Trace, TraceTable,
};

pub mod rescue;

// CONSTRAINT EVALUATION HELPERS
// ================================================================================================

/// Returns zero only when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

/// Returns zero only when a == zero.
pub fn is_zero<E: FieldElement>(a: E) -> E {
    a
}

/// Returns zero only when a = zero || a == one.
pub fn is_binary<E: FieldElement>(a: E) -> E {
    a * a - a
}

/// Return zero when a == one, and one when a == zero;
/// assumes that a is a binary value.
pub fn not<E: FieldElement>(a: E) -> E {
    E::ONE - a
}

// TRAIT TO SIMPLIFY CONSTRAINT AGGREGATION
// ================================================================================================

pub trait EvaluationResult<E> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

impl<E: FieldElement> EvaluationResult<E> for Vec<E> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

// OTHER FUNCTIONS
// ================================================================================================

/// Prints out an execution trace.
pub fn print_trace<E: StarkField>(
    trace: &TraceTable<E>,
    multiples_of: usize,
    offset: usize,
    range: Range<usize>,
) {
    let trace_width = trace.width();

    let mut state = vec![E::ZERO; trace_width];
    for i in 0..trace.length() {
        if (i.wrapping_sub(offset)) % multiples_of != 0 {
            continue;
        }
        trace.read_row_into(i, &mut state);
        println!(
            "{}\t{:?}",
            i,
            state[range.clone()]
                .iter()
                .map(|v| v.as_int())
                .collect::<Vec<E::PositiveInteger>>()
        );
    }
}

pub fn print_trace_step<E: StarkField>(trace: &[Vec<E>], step: usize) {
    let trace_width = trace.len();
    let mut state = vec![E::ZERO; trace_width];
    for i in 0..trace_width {
        state[i] = trace[i][step];
    }
    println!(
        "{}\t{:?}",
        step,
        state.iter().map(|v| v.as_int()).collect::<Vec<E::PositiveInteger>>()
    );
}
