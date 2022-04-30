// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{BaseElement, FieldElement, ProofOptions, ALPHA, FORTY_TWO};
use winterfell::{
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone)]
pub struct VdfInputs {
    pub seed: BaseElement,
    pub result: BaseElement,
}

impl Serializable for VdfInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.seed);
        target.write(self.result);
    }
}

// VDF AIR
// ================================================================================================

pub struct VdfAir {
    context: AirContext<BaseElement>,
    seed: BaseElement,
    result: BaseElement,
}

impl Air for VdfAir {
    type BaseField = BaseElement;
    type PublicInputs = VdfInputs;

    fn new(trace_info: TraceInfo, pub_inputs: VdfInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(3)];
        // make sure the last two rows are excluded from transition constraints as we populate
        // values in the last row with garbage
        let context =
            AirContext::new(trace_info, degrees, 2, options).set_num_transition_exemptions(2);
        Self {
            context,
            seed: pub_inputs.seed,
            result: pub_inputs.result,
        }
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_state = frame.current()[0];
        let next_state = frame.next()[0];

        result[0] = current_state - (next_state.exp(ALPHA.into()) + FORTY_TWO.into());
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // the second boundary constraint is applied to the second to last step
        // as the last step will contain garbage
        let second_to_last_step = self.trace_length() - 2;
        vec![
            Assertion::single(0, 0, self.seed),
            Assertion::single(0, second_to_last_step, self.result),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}
