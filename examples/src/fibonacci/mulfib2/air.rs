// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::are_equal;
use prover::{
    math::field::{f128::BaseElement, FieldElement},
    Air, Assertion, ComputationContext, EvaluationFrame, ExecutionTrace, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// FIBONACCI AIR
// ================================================================================================

const TRACE_WIDTH: usize = 2;

pub struct MulFib2Air {
    context: ComputationContext,
    result: BaseElement,
}

impl Air for MulFib2Air {
    type BaseElement = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseElement, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
        ];
        let context = ComputationContext::new(TRACE_WIDTH, trace_info.length, degrees, options);
        MulFib2Air {
            context,
            result: pub_inputs,
        }
    }

    fn context(&self) -> &ComputationContext {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = &frame.current;
        let next = &frame.next;
        // expected state width is 2 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // constraints of multiplicative Fibonacci (with 2 registers) which state that:
        // s_{0, i+1} = s_{0, i} * s_{1, i}
        // s_{1, i+1} = s_{1, i} * s_{0, i+1}
        result[0] = are_equal(next[0], current[0] * current[1]);
        result[1] = are_equal(next[1], current[1] * next[0]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        // a valid multiplicative Fibonacci sequence should start with 1, 2 and terminate
        // with the expected result
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, Self::BaseElement::new(1)),
            Assertion::single(1, 0, Self::BaseElement::new(2)),
            Assertion::single(0, last_step, self.result),
        ]
    }
}

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub fn build_trace(length: usize) -> ExecutionTrace<BaseElement> {
    assert!(
        length.is_power_of_two(),
        "sequence length must be a power of 2"
    );

    let mut reg0 = vec![BaseElement::new(1)];
    let mut reg1 = vec![BaseElement::new(2)];

    for i in 0..(length / 2 - 1) {
        reg0.push(reg0[i] * reg1[i]);
        reg1.push(reg1[i] * reg0[i + 1]);
    }

    ExecutionTrace::init(vec![reg0, reg1])
}
