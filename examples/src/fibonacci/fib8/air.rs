// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::are_equal;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    Air, AirContext, Assertion, EvaluationFrame, ExecutionTrace, ProofOptions, TraceBuilder,
    TraceInfo, TransitionConstraintDegree,
};

// FIBONACCI AIR
// ================================================================================================

const TRACE_WIDTH: usize = 2;

pub struct Fib8Air {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for Fib8Air {
    type BaseElement = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseElement, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        Fib8Air {
            context: AirContext::new(trace_info, degrees, options),
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseElement> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 2 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // constraints of Fibonacci sequence (2 registers, skipping over 8 terms):
        let n0 = current[0] + current[1];
        let n1 = current[1] + n0;
        let n2 = n0 + n1;
        let n3 = n1 + n2;
        let n4 = n2 + n3;
        let n5 = n3 + n4;
        let n6 = n4 + n5;
        let n7 = n5 + n6;

        result[0] = are_equal(next[0], n6);
        result[1] = are_equal(next[1], n7);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        // assert that the trace starts with 7th and 8th terms of Fibonacci sequence (the first
        // 6 terms are not recorded in the trace), and ends with the expected result
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, BaseElement::new(13)),
            Assertion::single(1, 0, BaseElement::new(21)),
            Assertion::single(1, last_step, self.result),
        ]
    }
}

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub struct Fib8TraceBuilder {
    sequence_length: usize,
}

impl Fib8TraceBuilder {
    pub fn new(sequence_length: usize) -> Self {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        Self { sequence_length }
    }
}

impl TraceBuilder for Fib8TraceBuilder {
    type BaseField = BaseElement;

    fn build_trace(&self) -> ExecutionTrace<Self::BaseField> {
        // initialize the trace with 7th and 8th terms of Fibonacci sequence (skipping the first 6)
        let n0 = BaseElement::ONE;
        let n1 = BaseElement::ONE;
        let n2 = n0 + n1;
        let n3 = n1 + n2;
        let n4 = n2 + n3;
        let n5 = n3 + n4;
        let n6 = n4 + n5;
        let n7 = n5 + n6;

        let mut reg0 = vec![n6];
        let mut reg1 = vec![n7];

        for i in 0..(self.sequence_length / 8 - 1) {
            let n0 = reg0[i] + reg1[i];
            let n1 = reg1[i] + n0;
            let n2 = n0 + n1;
            let n3 = n1 + n2;
            let n4 = n2 + n3;
            let n5 = n3 + n4;
            let n6 = n4 + n5;
            let n7 = n5 + n6;

            reg0.push(n6);
            reg1.push(n7);
        }

        ExecutionTrace::init(vec![reg0, reg1])
    }
}
