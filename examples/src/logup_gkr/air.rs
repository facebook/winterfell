// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::marker::PhantomData;

use winterfell::{
    math::{fields::f64::BaseElement, ExtensionOf, FieldElement, StarkField},
    Air, AirContext, Assertion, AuxRandElements, EvaluationFrame, LogUpGkrEvaluator,
    LogUpGkrOracle, TraceInfo, TransitionConstraintDegree,
};

use super::ProofOptions;

pub const NUM_FRACTIONS: usize = 64;

pub(crate) struct LogUpGkrSimpleAir {
    context: AirContext<BaseElement, ()>,
}

impl Air for LogUpGkrSimpleAir {
    type BaseField = BaseElement;
    type PublicInputs = ();

    fn new(trace_info: TraceInfo, _pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new_multi_segment(
                trace_info,
                _pub_inputs,
                vec![TransitionConstraintDegree::new(1)],
                vec![],
                1,
                0,
                options,
            ),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField, ()> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current()[0];
        let next = frame.next()[0];

        // increments by 1
        result[0] = next - current - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(0, 0, BaseElement::ZERO)]
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        _aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        _result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        // do nothing
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![]
    }

    fn get_logup_gkr_evaluator(
        &self,
    ) -> impl LogUpGkrEvaluator<BaseField = Self::BaseField, PublicInputs = Self::PublicInputs>
    {
        PlainLogUpGkrEval::new()
    }
}

#[derive(Clone, Default)]
pub struct PlainLogUpGkrEval<B: FieldElement + StarkField> {
    oracles: Vec<LogUpGkrOracle>,
    _field: PhantomData<B>,
}

impl<B: FieldElement + StarkField> PlainLogUpGkrEval<B> {
    pub fn new() -> Self {
        let committed_0 = LogUpGkrOracle::CurrentRow(0);
        let committed_1 = LogUpGkrOracle::CurrentRow(1);
        let committed_2 = LogUpGkrOracle::CurrentRow(2);
        let committed_3 = LogUpGkrOracle::CurrentRow(3);
        let committed_4 = LogUpGkrOracle::CurrentRow(4);
        let oracles = vec![committed_0, committed_1, committed_2, committed_3, committed_4];
        Self { oracles, _field: PhantomData }
    }
}

impl LogUpGkrEvaluator for PlainLogUpGkrEval<BaseElement> {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn get_oracles(&self) -> &[LogUpGkrOracle] {
        &self.oracles
    }

    fn get_num_rand_values(&self) -> usize {
        1
    }

    fn get_num_fractions(&self) -> usize {
        NUM_FRACTIONS
    }

    fn max_degree(&self) -> usize {
        10
    }

    fn build_query<E>(&self, frame: &EvaluationFrame<E>, query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        query.iter_mut().zip(frame.current().iter()).for_each(|(q, f)| *q = *f)
    }

    fn evaluate_query<F, E>(
        &self,
        query: &[F],
        _periodic_values: &[F],
        rand_values: &[E],
        numerator: &mut [E],
        denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        assert_eq!(numerator.len(), self.get_num_fractions());
        assert_eq!(denominator.len(), self.get_num_fractions());
        assert_eq!(query.len(), 5);

        for i in (0..self.get_num_fractions()).step_by(4) {
            numerator[i] = E::from(query[1]);
            numerator[i + 1] = E::ONE;
            numerator[i + 2] = E::ONE;
            numerator[i + 3] = E::ONE;
        }

        for i in (0..self.get_num_fractions()).step_by(4) {
            denominator[i] = rand_values[0] - E::from(query[0]);
            denominator[i + 1] = -(rand_values[0] - E::from(query[2]));
            denominator[i + 2] = -(rand_values[0] - E::from(query[3]));
            denominator[i + 3] = -(rand_values[0] - E::from(query[4]));
        }
    }

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        E::ZERO
    }
}
