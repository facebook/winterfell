// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::FieldElement;

use super::{super::Air, EvaluationFrame, GkrData};
use crate::LogUpGkrEvaluator;

/// Represents the transition constraint for the s-column, as well as the random coefficient used
/// to linearly combine the constraint into the constraint composition polynomial.
///
/// The s-column implements the cohomological sum-check argument of [1] and the constraint in
/// [`SColumnConstraint`] is exactly Eq (4) in Lemma 1 in [1].
///
///
/// [1]: https://eprint.iacr.org/2021/930
pub struct SColumnConstraint<E: FieldElement> {
    gkr_data: GkrData<E>,
    composition_coefficient: E,
}

impl<E: FieldElement> SColumnConstraint<E> {
    pub fn new(gkr_data: GkrData<E>, composition_coefficient: E) -> Self {
        Self { gkr_data, composition_coefficient }
    }

    /// Evaluates the transition constraint over the specificed main trace segment, s-column,
    /// and Lagrange kernel evaluation frames.
    pub fn evaluate<A>(
        &self,
        air: &A,
        main_trace_frame: &EvaluationFrame<E>,
        s_cur: E,
        s_nxt: E,
        l_cur: E,
        x: E,
    ) -> E
    where
        A: Air<BaseField = E::BaseField>,
    {
        let batched_claim = self.gkr_data.compute_batched_claim();
        let mean = batched_claim
            .mul_base(E::BaseField::ONE / E::BaseField::from(air.trace_length() as u32));

        let mut query = vec![E::ZERO; air.get_logup_gkr_evaluator().get_oracles().len()];
        air.get_logup_gkr_evaluator().build_query(main_trace_frame, &mut query);
        let batched_claim_at_query = self.gkr_data.compute_batched_query::<E>(&query);
        let rhs = s_cur - mean + batched_claim_at_query * l_cur;
        let lhs = s_nxt;

        let divisor = x.exp((air.trace_length() as u32).into()) - E::ONE;
        self.composition_coefficient * (rhs - lhs) / divisor
    }
}
