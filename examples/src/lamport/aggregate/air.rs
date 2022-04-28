// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    rescue, CYCLE_LENGTH as HASH_CYCLE_LEN, SIG_CYCLE_LENGTH as SIG_CYCLE_LEN, TRACE_WIDTH,
};
use crate::utils::{are_equal, is_binary, is_zero, not, EvaluationResult};
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================
const TWO: BaseElement = BaseElement::new(2);

// AGGREGATE LAMPORT PLUS SIGNATURE AIR
// ================================================================================================

#[derive(Clone)]
pub struct PublicInputs {
    pub pub_keys: Vec<[BaseElement; 2]>,
    pub messages: Vec<[BaseElement; 2]>,
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.pub_keys);
        target.write(&self.messages);
    }
}

pub struct LamportAggregateAir {
    context: AirContext<BaseElement>,
    pub_keys: Vec<[BaseElement; 2]>,
    messages: Vec<[BaseElement; 2]>,
}

impl Air for LamportAggregateAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // define degrees for all transition constraints
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(2, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]), // m0 bit is binary
            TransitionConstraintDegree::with_cycles(2, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]), // m1 bit is binary
            TransitionConstraintDegree::with_cycles(
                1,
                vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN, SIG_CYCLE_LEN],
            ), // m0 accumulation
            TransitionConstraintDegree::with_cycles(
                1,
                vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN, SIG_CYCLE_LEN],
            ), // m1 accumulation
            // secret key 1 hashing
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            // secret key 2 hashing
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            // public key hashing
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        LamportAggregateAir {
            context: AirContext::new(trace_info, degrees, 22, options),
            pub_keys: pub_inputs.pub_keys,
            messages: pub_inputs.messages,
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
        // expected state width is 4 field elements
        debug_assert_eq!(TRACE_WIDTH, current.len());
        debug_assert_eq!(TRACE_WIDTH, next.len());

        // spit periodic values into flags and Rescue round constants
        let sig_cycle_end_flag = periodic_values[0];
        let power_of_two = periodic_values[1];
        let hash_flag = periodic_values[2];
        let ark = &periodic_values[3..];

        // evaluate the constraints
        evaluate_constraints(
            result,
            current,
            next,
            ark,
            hash_flag,
            sig_cycle_end_flag,
            power_of_two,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_cycle_step = SIG_CYCLE_LEN - 1;
        let messages = transpose(&self.messages);
        let pub_keys = transpose(&self.pub_keys);
        vec![
            // --- set assertions against the first step of every cycle: 0, 1024, 2048 etc. -------
            // message aggregators should be set to zeros
            Assertion::periodic(2, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(3, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            // for private key hasher, last 4 state register should be set to zeros
            Assertion::periodic(6, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(7, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(8, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(9, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(12, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(13, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(14, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(15, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            // for public key hasher, all registers should be set to zeros
            Assertion::periodic(16, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(17, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(18, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(19, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(20, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(21, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            // --- set assertions against the last step of every cycle: 1023, 2047, 3071 etc. -----
            // last bits of message bit registers should be set to zeros; this is because we truncate
            // message elements to 127 bits each - so, 128th bit must always be zero
            Assertion::periodic(0, last_cycle_step, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(1, last_cycle_step, SIG_CYCLE_LEN, BaseElement::ZERO),
            // message accumulator registers should be set to message element values
            Assertion::sequence(2, last_cycle_step, SIG_CYCLE_LEN, messages.0),
            Assertion::sequence(3, last_cycle_step, SIG_CYCLE_LEN, messages.1),
            // public key hasher should terminate with public key elements
            Assertion::sequence(16, last_cycle_step, SIG_CYCLE_LEN, pub_keys.0),
            Assertion::sequence(17, last_cycle_step, SIG_CYCLE_LEN, pub_keys.1),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut result = vec![];

        // signature cycle mask: 1023 zeros followed by 1 one
        let mut sig_cycle_mask = vec![BaseElement::ZERO; SIG_CYCLE_LEN];
        sig_cycle_mask[SIG_CYCLE_LEN - 1] = BaseElement::ONE;
        result.push(sig_cycle_mask);

        // build powers of two column
        let mut powers_of_two = vec![BaseElement::ZERO; SIG_CYCLE_LEN];
        let mut current_power_of_two = BaseElement::ONE;
        powers_of_two[0] = BaseElement::ONE;
        for (i, value) in powers_of_two.iter_mut().enumerate().skip(1) {
            // we switch to a new power of two once every 8 steps this. is so that a
            // new power of two is available for every hash cycle
            if i % HASH_CYCLE_LEN == 0 {
                current_power_of_two *= TWO;
            }
            *value = current_power_of_two;
        }
        result.push(powers_of_two);

        // add hash cycle mask (seven ones followed by a zero), and rescue round constants
        result.push(HASH_CYCLE_MASK.to_vec());
        result.append(&mut rescue::get_round_constants());

        result
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[rustfmt::skip]
fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    hash_flag: E,
    sig_cycle_end_flag: E,
    power_of_two: E,
) {
    // when hash_flag = 1 (which happens on all steps except steps which are one less than a
    // multiple of 8 - e.g. all steps except for 7, 15, 23 etc.), and we are not on the last step
    // of a signature cycle make sure the contents of the first 4 registers are copied over, and
    // for other registers, Rescue constraints are applied separately for hashing secret and
    // public keys
    let flag = not(sig_cycle_end_flag) * hash_flag;
    result.agg_constraint(0, flag, are_equal(current[0], next[0]));
    result.agg_constraint(1, flag, are_equal(current[1], next[1]));
    result.agg_constraint(2, flag, are_equal(current[2], next[2]));
    result.agg_constraint(3, flag, are_equal(current[3], next[3]));
    rescue::enforce_round(&mut result[4..10],  &current[4..10],  &next[4..10],  ark, flag);
    rescue::enforce_round(&mut result[10..16], &current[10..16], &next[10..16], ark, flag);
    rescue::enforce_round(&mut result[16..22], &current[16..22], &next[16..22], ark, flag);

    // when hash_flag = 0 (which happens on steps which are one less than a multiple of 8 - e.g. 7,
    // 15, 23 etc.), and we are not on the last step of a signature cycle:
    let flag = not(sig_cycle_end_flag) * not(hash_flag);
    // make sure values inserted into registers 0 and 1 are binary
    result.agg_constraint(0, flag, is_binary(current[0]));
    result.agg_constraint(1, flag, is_binary(current[1]));
    // make sure message values were aggregated correctly in registers 2 and 3
    let next_m0 = current[2] + current[0] * power_of_two;
    result.agg_constraint(2, flag, are_equal(next_m0, next[2]));
    let next_m1 = current[3] + current[1] * power_of_two;
    result.agg_constraint(3, flag, are_equal(next_m1, next[3]));

    // registers 6..10 and 12..16 were set to zeros
    result.agg_constraint(4, flag, is_zero(next[6]));
    result.agg_constraint(5, flag, is_zero(next[7]));
    result.agg_constraint(6, flag, is_zero(next[8]));
    result.agg_constraint(7, flag, is_zero(next[9]));
    result.agg_constraint(8, flag, is_zero(next[12]));
    result.agg_constraint(9, flag, is_zero(next[13]));
    result.agg_constraint(10, flag, is_zero(next[14]));
    result.agg_constraint(11, flag, is_zero(next[15]));

    // contents of registers 20 and 21 (capacity section of public key hasher state) were
    // copied over to the next step
    result.agg_constraint(12, flag, are_equal(current[20], next[20]));
    result.agg_constraint(13, flag, are_equal(current[21], next[21]));

    // when current bit of m0 = 1, hash of private key 1 (which should be equal to public key)
    // should be injected into the hasher state for public key aggregator
    let m0_bit = current[0];
    result.agg_constraint(14, flag * m0_bit,are_equal(current[16] + current[4], next[16]));
    result.agg_constraint(15, flag * m0_bit, are_equal(current[17] + current[5], next[17]));

    // when current bit of m1 = 1, hash of private key 2 (which should be equal to public key)
    // should be injected into the hasher state for public key aggregator
    let m1_bit = current[1];
    result.agg_constraint(16, flag * m1_bit, are_equal(current[18] + current[10], next[18]));
    result.agg_constraint(17, flag * m1_bit, are_equal(current[19] + current[11], next[19]));
}

fn transpose(values: &[[BaseElement; 2]]) -> (Vec<BaseElement>, Vec<BaseElement>) {
    let n = values[0].len();
    let mut r1 = Vec::with_capacity(n);
    let mut r2 = Vec::with_capacity(n);
    for element in values {
        r1.push(element[0]);
        r2.push(element[1]);
    }
    (r1, r2)
}

// MASKS
// ================================================================================================
const HASH_CYCLE_MASK: [BaseElement; HASH_CYCLE_LEN] = [
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ONE,
    BaseElement::ZERO,
];
