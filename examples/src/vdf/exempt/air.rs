// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::marker::PhantomData;

use air::LogUpGkrEvaluator;
use winterfell::{
    math::ToElements, Air, AirContext, Assertion, EvaluationFrame, TraceInfo,
    TransitionConstraintDegree,
};

use super::{BaseElement, FieldElement, ProofOptions, ALPHA, FORTY_TWO, TRACE_WIDTH};

// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone)]
pub struct VdfInputs {
    pub seed: BaseElement,
    pub result: BaseElement,
}

impl ToElements<BaseElement> for VdfInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.seed, self.result]
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
    type LogUpGkrEvaluator = PlainLogUpGkrEval<Self::BaseField>;

    fn new(trace_info: TraceInfo, pub_inputs: VdfInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(3)];
        assert_eq!(TRACE_WIDTH, trace_info.width());
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

#[derive(Clone, Default)]
pub struct PlainLogUpGkrEval<B: FieldElement> {
    _field: PhantomData<B>,
}

impl LogUpGkrEvaluator for PlainLogUpGkrEval<BaseElement> {
    type BaseField = BaseElement;

    type PublicInputs = VdfInputs;

    fn get_oracles(&self) -> &[air::LogUpGkrOracle<Self::BaseField>] {
        unimplemented!()
    }

    fn get_num_rand_values(&self) -> usize {
        unimplemented!()
    }

    fn get_num_fractions(&self) -> usize {
        unimplemented!()
    }

    fn max_degree(&self) -> usize {
        unimplemented!()
    }

    fn build_query<E>(&self, _frame: &EvaluationFrame<E>, _periodic_values: &[E], _query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        unimplemented!()
    }

    fn evaluate_query<F, E>(
        &self,
        _query: &[F],
        _rand_values: &[E],
        _numerator: &mut [E],
        _denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + winterfell::math::ExtensionOf<F>,
    {
        unimplemented!()
    }

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        unimplemented!()
    }
}
