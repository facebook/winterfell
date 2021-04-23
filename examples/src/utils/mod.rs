// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use prover::{
    math::{
        field::{f128::BaseElement, FieldElement, StarkField},
        utils::read_elements_into_vec,
    },
    ExecutionTrace,
};
use std::{convert::TryInto, ops::Range};

pub mod rescue;

// CONSTRAINT EVALUATION HELPERS
// ================================================================================================

pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

pub fn is_zero<E: FieldElement>(a: E) -> E {
    a
}

pub fn is_binary<E: FieldElement>(a: E) -> E {
    a * a - a
}

pub fn not<E: FieldElement>(a: E) -> E {
    E::ONE - a
}

pub fn when<E: FieldElement>(a: E, b: E) -> E {
    a * b
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

// MERKLE TREE FUNCTIONS
// ================================================================================================

pub type TreeNode = (BaseElement, BaseElement);

pub fn node_to_bytes(node: TreeNode) -> [u8; 32] {
    BaseElement::elements_as_bytes(&[node.0, node.1])
        .try_into()
        .unwrap()
}

pub fn bytes_to_node(bytes: [u8; 32]) -> TreeNode {
    let elements = read_elements_into_vec(&bytes).unwrap();
    (elements[0], elements[1])
}

// OTHER FUNCTIONS
// ================================================================================================

/// Prints out an execution trace.
pub fn print_trace(
    trace: &ExecutionTrace<BaseElement>,
    multiples_of: usize,
    offset: usize,
    range: Range<usize>,
) {
    let trace_width = trace.len();

    let mut state = vec![BaseElement::ZERO; trace_width];
    for i in 0..trace.len() {
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
                .collect::<Vec<u128>>()
        );
    }
}

pub fn print_trace_step(trace: &[Vec<BaseElement>], step: usize) {
    let trace_width = trace.len();
    let mut state = vec![BaseElement::ZERO; trace_width];
    for i in 0..trace_width {
        state[i] = trace[i][step];
    }
    println!(
        "{}\t{:?}",
        step,
        state.iter().map(|v| v.as_int()).collect::<Vec<u128>>()
    );
}
