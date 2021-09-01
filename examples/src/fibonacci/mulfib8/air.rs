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

const TRACE_WIDTH: usize = 8;

pub struct MulFib8Air {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for MulFib8Air {
    type BaseElement = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseElement, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        MulFib8Air {
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

        // constraints of multiplicative Fibonacci (with 8 registers) which state that:
        // s_{0, i+1} = s_{6, i} * s_{7, i}
        // s_{1, i+1} = s_{7, i} * s_{0, i+1}
        // s_{2, i+1} = s_{0, i+1} * s_{1, i+1}
        // s_{3, i+1} = s_{1, i+1} * s_{2, i+1}
        // s_{4, i+1} = s_{2, i+1} * s_{3, i+1}
        // s_{5, i+1} = s_{3, i+1} * s_{4, i+1}
        // s_{6, i+1} = s_{4, i+1} * s_{5, i+1}
        // s_{7, i+1} = s_{5, i+1} * s_{6, i+1}
        result[0] = are_equal(next[0], current[6] * current[7]);
        result[1] = are_equal(next[1], current[7] * next[0]);
        result[2] = are_equal(next[2], next[0] * next[1]);
        result[3] = are_equal(next[3], next[1] * next[2]);
        result[4] = are_equal(next[4], next[2] * next[3]);
        result[5] = are_equal(next[5], next[3] * next[4]);
        result[6] = are_equal(next[6], next[4] * next[5]);
        result[7] = are_equal(next[7], next[5] * next[6]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>> {
        // a valid multiplicative Fibonacci sequence should start with 1, 2 and terminate
        // with the expected result
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, BaseElement::new(1)),
            Assertion::single(1, 0, BaseElement::new(2)),
            Assertion::single(6, last_step, self.result),
        ]
    }
}

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub struct MulFib8TraceBuilder {
    sequence_length: usize,
}

impl MulFib8TraceBuilder {
    pub fn new(sequence_length: usize) -> Self {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        Self { sequence_length }
    }
}

impl TraceBuilder for MulFib8TraceBuilder {
    type BaseField = BaseElement;

    fn build_trace(&self) -> ExecutionTrace<Self::BaseField> {
        let mut reg0 = vec![BaseElement::new(1)];
        let mut reg1 = vec![BaseElement::new(2)];
        let mut reg2 = vec![reg0[0] * reg1[0]];
        let mut reg3 = vec![reg1[0] * reg2[0]];
        let mut reg4 = vec![reg2[0] * reg3[0]];
        let mut reg5 = vec![reg3[0] * reg4[0]];
        let mut reg6 = vec![reg4[0] * reg5[0]];
        let mut reg7 = vec![reg5[0] * reg6[0]];

        for i in 0..(self.sequence_length / 8 - 1) {
            reg0.push(reg6[i] * reg7[i]);
            reg1.push(reg7[i] * reg0[i + 1]);
            reg2.push(reg0[i + 1] * reg1[i + 1]);
            reg3.push(reg1[i + 1] * reg2[i + 1]);
            reg4.push(reg2[i + 1] * reg3[i + 1]);
            reg5.push(reg3[i + 1] * reg4[i + 1]);
            reg6.push(reg4[i + 1] * reg5[i + 1]);
            reg7.push(reg5[i + 1] * reg6[i + 1]);
        }

        ExecutionTrace::init(vec![reg0, reg1, reg2, reg3, reg4, reg5, reg6, reg7])
    }
}
