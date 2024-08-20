// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use super::{BaseElement, FieldElement, TRACE_WIDTH};
use crate::utils::are_equal;

// FIBONACCI AIR
// ================================================================================================

pub struct Fib8Air {
    context: AirContext<BaseElement, BaseElement>,
    result: BaseElement,
}

impl Air for Fib8Air {
    type BaseField = BaseElement;
    type PublicInputs = BaseElement;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: Self::BaseField, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(1), TransitionConstraintDegree::new(1)];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        Fib8Air {
            context: AirContext::new(trace_info, pub_inputs, degrees, 3, options),
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField, Self::PublicInputs> {
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

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
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

#[derive(Clone, Default)]
pub struct PlainLogUpGkrEval<B: FieldElement> {
    _field: std::marker::PhantomData<B>,
}

impl air::LogUpGkrEvaluator for PlainLogUpGkrEval<BaseElement> {
    type BaseField = BaseElement;

    type PublicInputs = BaseElement;

    fn get_oracles(&self) -> Vec<air::LogUpGkrOracle<Self::BaseField>> {
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
