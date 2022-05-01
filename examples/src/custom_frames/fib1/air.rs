// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{BaseElement, FibEvaluationFrame, FieldElement, ProofOptions, TRACE_WIDTH};
use crate::utils::are_equal;
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, TraceInfo, TransitionConstraintDegree,
};

// FIBONACCI AIR
// ================================================================================================

pub struct FibAir {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl Air for FibAir {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;
    type Frame<E: FieldElement> = FibEvaluationFrame<E>;
    type AuxFrame<E: FieldElement> = FibEvaluationFrame<E>;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseField, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(1)];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        let context =
            AirContext::new(trace_info, degrees, 3, options).set_num_transition_exemptions(2);
        FibAir {
            context,
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &Self::Frame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let row_0 = frame.row(0);
        let row_1 = frame.row(1);
        let row_2 = frame.row(2);

        // expected state width is 1 field elements
        debug_assert_eq!(TRACE_WIDTH, row_0.len());
        debug_assert_eq!(TRACE_WIDTH, row_1.len());
        debug_assert_eq!(TRACE_WIDTH, row_2.len());

        // constraints of Fibonacci sequence
        result[0] = are_equal(row_2[0], row_0[0] + row_1[0]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // a valid Fibonacci sequence should start with two ones and terminate with
        // the expected result
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, Self::BaseField::ONE),
            Assertion::single(0, 1, Self::BaseField::ONE),
            Assertion::single(0, last_step, self.result),
        ]
    }
}
