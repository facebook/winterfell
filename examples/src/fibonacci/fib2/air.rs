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

pub struct FibAir {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for FibAir {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseField, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        FibAir {
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

        // constraints of Fibonacci sequence (2 terms per step):
        // s_{0, i+1} = s_{0, i} + s_{1, i}
        // s_{1, i+1} = s_{1, i} + s_{0, i+1}
        result[0] = are_equal(next[0], current[0] + current[1]);
        result[1] = are_equal(next[1], current[1] + next[0]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // a valid Fibonacci sequence should start with two ones and terminate with
        // the expected result
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, Self::BaseField::ONE),
            Assertion::single(1, 0, Self::BaseField::ONE),
            Assertion::single(1, last_step, self.result),
        ]
    }
}

// FIBONACCI TRACE BUILDER
// ================================================================================================

pub struct FibTraceBuilder {
    trace_info: TraceInfo,
}

impl FibTraceBuilder {
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

impl TraceBuilder for FibTraceBuilder {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;

    fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }

    fn init_state(&self, state: &mut [Self::BaseField], _segment: usize) {
        state[0] = BaseElement::ONE;
        state[1] = BaseElement::ONE;
    }

    fn update_state(&self, state: &mut [Self::BaseField], _step: usize, _segment: usize) {
        state[0] += state[1];
        state[1] += state[0];
    }

    fn get_pub_inputs(&self, trace: &TraceTable<Self::BaseField>) -> Self::PublicInputs {
        let last_step = trace.length() - 1;
        trace.get(1, last_step)
    }
}
