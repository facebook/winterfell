// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    rescue::{self, STATE_WIDTH},
    BaseElement, ExtensionOf, FieldElement, ProofOptions, CYCLE_LENGTH, TRACE_WIDTH,
};
use crate::utils::{are_equal, not, EvaluationResult};
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
    pub result: [[BaseElement; 2]; 2],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.result[..]);
    }
}

pub struct RescueRapsAir {
    context: AirContext<BaseElement>,
    result: [[BaseElement; 2]; 2],
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
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(1, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::new(2),
        ];
        assert_eq!(TRACE_WIDTH + 3, trace_info.width());
        RescueRapsAir {
            context: AirContext::new_multi_segment(
                trace_info,
                main_degrees,
                aux_degrees,
                8,
                2,
                options,
            ),
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

        // split periodic values into hash_flag, absorption flag and Rescue round constants
        let hash_flag = periodic_values[0];
        let absorption_flag = periodic_values[1];
        let ark = &periodic_values[2..];

        // when hash_flag = 1, constraints for Rescue round are enforced (steps 0 to 14)
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

        // When absorbing the additional seeds (step 14), we do not verify correctness of the
        // rate registers. Instead, we only verify that capacity registers have not
        // changed. When computing the permutation argument, we will recompute the permuted
        // values from the contiguous rows.
        // At step 15, we enforce that the whole hash states are copied to the next step,
        // enforcing that the values added to the capacity registers at step 14 and used in the
        // permutation argument are the ones being used in the next hashing sequence.
        result.agg_constraint(2, absorption_flag, are_equal(current[2], next[2]));
        result.agg_constraint(3, absorption_flag, are_equal(current[3], next[3]));

        result.agg_constraint(6, absorption_flag, are_equal(current[6], next[6]));
        result.agg_constraint(7, absorption_flag, are_equal(current[7], next[7]));

        // when hash_flag + absorption_flag = 0, constraints for copying hash values to the
        // next step are enforced.
        let copy_flag = not(hash_flag + absorption_flag);
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
        let main_next = main_frame.next();

        let aux_current = aux_frame.current();
        let aux_next = aux_frame.next();

        let random_elements = aux_rand_elements.get_segment_elements(0);

        let absorption_flag = periodic_values[1];

        // We want to enforce that the absorbed values of the first hash chain are a
        // permutation of the absorbed values of the second one. Because we want to
        // copy two values per hash chain (namely the two capacity registers), we
        // group them with random elements into a single cell via
        // α_0 * c_0 + α_1 * c_1, where c_i is computed as next_i - current_i.

        // Note that storing the copied values into two auxiliary columns. One could
        // instead directly compute the permutation argument, hence require a single
        // auxiliary one. For the sake of illustrating RAPs behaviour, we will store
        // the computed values in additional columns.

        let copied_value_1 = random_elements[0] * (main_next[0] - main_current[0]).into()
            + random_elements[1] * (main_next[1] - main_current[1]).into();

        result.agg_constraint(
            0,
            absorption_flag.into(),
            are_equal(aux_current[0], copied_value_1),
        );

        let copied_value_2 = random_elements[0] * (main_next[4] - main_current[4]).into()
            + random_elements[1] * (main_next[5] - main_current[5]).into();

        result.agg_constraint(
            1,
            absorption_flag.into(),
            are_equal(aux_current[1], copied_value_2),
        );

        // Enforce that the permutation argument column scales at each step by (aux[0] + γ) / (aux[1] + γ).
        result.agg_constraint(
            2,
            E::ONE,
            are_equal(
                aux_next[2] * (aux_current[1] + random_elements[2]),
                aux_current[2] * (aux_current[0] + random_elements[2]),
            ),
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Assert starting and ending values of the hash chain
        let last_step = self.trace_length() - 1;
        vec![
            // Initial capacity registers must be set to zero
            Assertion::single(2, 0, BaseElement::ZERO),
            Assertion::single(3, 0, BaseElement::ZERO),
            Assertion::single(6, 0, BaseElement::ZERO),
            Assertion::single(7, 0, BaseElement::ZERO),
            // Final rate registers (digests) should be equal to
            // the provided public input
            Assertion::single(0, last_step, self.result[0][0]),
            Assertion::single(1, last_step, self.result[0][1]),
            Assertion::single(4, last_step, self.result[1][0]),
            Assertion::single(5, last_step, self.result[1][1]),
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
        let mut absorption_column = vec![BaseElement::ZERO; CYCLE_LENGTH];
        absorption_column[14] = BaseElement::ONE;
        result.push(absorption_column);

        result.append(&mut rescue::get_round_constants());

        result
    }
}

// HELPER EVALUATORS
// ------------------------------------------------------------------------------------------------

/// when flag = 1, enforces that the next state of the computation is defined like so:
/// - the first two registers are equal to the values from the previous step
/// - the other two registers are not restrained, they could be arbitrary elements,
///   until the RAP columns enforces that they are a permutation of the two final registers
///   of the other parallel chain
fn enforce_hash_copy<E: FieldElement>(result: &mut [E], current: &[E], next: &[E], flag: E) {
    result.agg_constraint(0, flag, are_equal(current[0], next[0]));
    result.agg_constraint(1, flag, are_equal(current[1], next[1]));
    result.agg_constraint(2, flag, are_equal(current[2], next[2]));
    result.agg_constraint(3, flag, are_equal(current[3], next[3]));
}
