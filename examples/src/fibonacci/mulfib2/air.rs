// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::utils::are_equal;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceBuilder, TraceInfo, TraceTable,
    TransitionConstraintDegree,
};

// FIBONACCI AIR
// ================================================================================================

const TRACE_WIDTH: usize = 2;

pub struct MulFib2Air {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for MulFib2Air {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseField, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(2),
            TransitionConstraintDegree::new(2),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        MulFib2Air {
            context: AirContext::new(trace_info, degrees, options),
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
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

        // constraints of multiplicative Fibonacci (with 2 registers) which state that:
        // s_{0, i+1} = s_{0, i} * s_{1, i}
        // s_{1, i+1} = s_{1, i} * s_{0, i+1}
        result[0] = are_equal(next[0], current[0] * current[1]);
        result[1] = are_equal(next[1], current[1] * next[0]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // a valid multiplicative Fibonacci sequence should start with 1, 2 and terminate
        // with the expected result
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, Self::BaseField::new(1)),
            Assertion::single(1, 0, Self::BaseField::new(2)),
            Assertion::single(0, last_step, self.result),
        ]
    }
}

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub struct MulFib2TraceBuilder {
    trace_info: TraceInfo,
}

impl MulFib2TraceBuilder {
    pub fn new(sequence_length: usize) -> Self {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        let trace_length = sequence_length / 2;
        let trace_info = TraceInfo::new(TRACE_WIDTH, trace_length);

        Self { trace_info }
    }
}

impl TraceBuilder for MulFib2TraceBuilder {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;

    fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }

    fn init_state(&self, state: &mut [Self::BaseField], _segment: usize) {
        state[0] = BaseElement::new(1);
        state[1] = BaseElement::new(2);
    }

    fn update_state(&self, state: &mut [Self::BaseField], _step: usize, _segment: usize) {
        state[0] *= state[1];
        state[1] *= state[0];
    }

    fn get_pub_inputs(&self, trace: &TraceTable<Self::BaseField>) -> Self::PublicInputs {
        let last_step = trace.length() - 1;
        trace.get(0, last_step)
    }
}
