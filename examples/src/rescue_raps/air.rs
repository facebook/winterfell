// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    rescue::{self, STATE_WIDTH},
    BaseElement, ExtensionOf, FieldElement, ProofOptions, CYCLE_LENGTH, TRACE_WIDTH,
};
use crate::utils::{are_equal, is_zero, not, EvaluationResult};
use winterfell::{
    Air, AirContext, Assertion, AuxTraceRandElements, ByteWriter, EvaluationFrame, Serializable,
    TraceInfo, TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================

/// Specifies steps on which Rescue transition function is applied.
const CYCLE_MASK: [BaseElement; CYCLE_LENGTH] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
    BaseElement::ZERO,
];

// RESCUE AIR
// ================================================================================================

pub struct PublicInputs {
    pub seed: [BaseElement; 2],
    pub result: [BaseElement; 2],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.seed[..]);
        target.write(&self.result[..]);
    }
}

pub struct RescueRapsAir {
    context: AirContext<BaseElement>,
    seed: [BaseElement; 2],
    result: [BaseElement; 2],
}

impl Air for RescueRapsAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let main_degrees =
            vec![TransitionConstraintDegree::with_cycles(3, vec![CYCLE_LENGTH]); 2 * STATE_WIDTH];
        let aux_degrees = vec![
            TransitionConstraintDegree::with_cycles(1, vec![trace_info.length()]),
            TransitionConstraintDegree::with_cycles(1, vec![trace_info.length()]),
            TransitionConstraintDegree::new(2),
        ];
        assert_eq!(TRACE_WIDTH + 3, trace_info.width());
        RescueRapsAir {
            context: AirContext::new_multi_segment(
                trace_info,
                main_degrees,
                aux_degrees,
                4,
                2,
                options,
            ),
            seed: pub_inputs.seed,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        // expected state width is 2*4 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // split periodic values into hash_flag and Rescue round constants
        let hash_flag = periodic_values[0];
        let ark = &periodic_values[1..STATE_WIDTH * 2 + 1];

        // when hash_flag = 1, constraints for Rescue round are enforced
        rescue::enforce_round(
            &mut result[..STATE_WIDTH],
            &current[..STATE_WIDTH],
            &next[..STATE_WIDTH],
            ark,
            hash_flag,
        );

        rescue::enforce_round(
            &mut result[STATE_WIDTH..],
            &current[STATE_WIDTH..],
            &next[STATE_WIDTH..],
            ark,
            hash_flag,
        );

        // when hash_flag = 0, constraints for copying hash values to the next
        // step are enforced.
        let copy_flag = not(hash_flag);
        enforce_hash_copy(
            &mut result[..STATE_WIDTH],
            &current[..STATE_WIDTH],
            &next[..STATE_WIDTH],
            copy_flag,
        );
        enforce_hash_copy(
            &mut result[STATE_WIDTH..],
            &current[STATE_WIDTH..],
            &next[STATE_WIDTH..],
            copy_flag,
        );
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        main_frame: &EvaluationFrame<F>,
        aux_frame: &EvaluationFrame<E>,
        periodic_values: &[F],
        aux_rand_elements: &AuxTraceRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        let main_current = main_frame.current();
        let _main_next = main_frame.next();

        let aux_current = aux_frame.current();
        let aux_next = aux_frame.next();

        let random_elements = aux_rand_elements.get_segment_elements(0);

        let copy_flag_1 = periodic_values[STATE_WIDTH * 2 + 1];
        let copy_flag_2 = periodic_values[STATE_WIDTH * 2 + 2];

        let copied_value_1 = main_current
            .iter()
            .take(4)
            .enumerate()
            .fold(E::ZERO, |acc, (idx, &cell)| {
                acc + random_elements[idx] * cell.into()
            });

        result.agg_constraint(
            0,
            copy_flag_1.into(),
            are_equal(aux_current[0], copied_value_1),
        );

        let copied_value_2 = main_current
            .iter()
            .skip(4)
            .take(4)
            .enumerate()
            .fold(E::ZERO, |acc, (idx, &cell)| {
                acc + random_elements[idx] * cell.into()
            });

        result.agg_constraint(
            1,
            copy_flag_2.into(),
            are_equal(aux_current[1], copied_value_2),
        );

        // Enforce that the permutation argument column scales at each step by (aux[0] + γ) / (aux[1] + γ).
        result.agg_constraint(
            2,
            E::ONE,
            are_equal(
                aux_next[2] * (aux_current[1] + random_elements[4]),
                aux_current[2] * (aux_current[0] + random_elements[4]),
            ),
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert starting and ending values of the hash chain
        let last_step = self.trace_length() - 1;
        vec![
            // We start the hash chain on columns 0-3
            Assertion::single(0, 0, self.seed[0]),
            Assertion::single(1, 0, self.seed[1]),
            // We end the hash chain on columns 4-7
            Assertion::single(4, last_step, self.result[0]),
            Assertion::single(5, last_step, self.result[1]),
        ]
    }

    fn get_aux_assertions<E: FieldElement + From<Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxTraceRandElements<E>,
    ) -> Vec<Assertion<E>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(2, 0, E::ONE),
            Assertion::single(2, last_step, E::ONE),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![CYCLE_MASK.to_vec()];
        result.append(&mut rescue::get_round_constants());

        let mut copy_column1 = vec![Self::BaseField::ZERO; self.trace_length()];
        let mut copy_column2 = copy_column1.clone();
        copy_column1[self.trace_length() - 1] = Self::BaseField::ONE;
        copy_column2[0] = Self::BaseField::ONE;

        result.push(copy_column1);
        result.push(copy_column2);

        result
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first two registers are equal to the values from the previous step
/// - the other two registers are equal to 0
fn enforce_hash_copy<E: FieldElement>(result: &mut [E], current: &[E], next: &[E], flag: E) {
    result.agg_constraint(0, flag, are_equal(current[0], next[0]));
    result.agg_constraint(1, flag, are_equal(current[1], next[1]));
    result.agg_constraint(2, flag, is_zero(next[2]));
    result.agg_constraint(3, flag, is_zero(next[3]));
}
