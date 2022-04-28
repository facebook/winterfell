// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    super::rescue, HASH_CYCLE_LENGTH as HASH_CYCLE_LEN, SIG_CYCLE_LENGTH as SIG_CYCLE_LEN,
    TRACE_WIDTH,
};
use crate::utils::{are_equal, is_binary, is_zero, not, EvaluationResult};
use winterfell::{
    math::{fields::f128::BaseElement, log2, FieldElement, StarkField},
    Air, AirContext, Assertion, ByteWriter, EvaluationFrame, ProofOptions, Serializable, TraceInfo,
    TransitionConstraintDegree,
};

// CONSTANTS
// ================================================================================================
const TWO: BaseElement = BaseElement::new(2);

// THRESHOLD LAMPORT PLUS SIGNATURE AIR
// ================================================================================================

#[derive(Clone)]
pub struct PublicInputs {
    pub pub_key_root: [BaseElement; 2],
    pub num_pub_keys: usize,
    pub num_signatures: usize,
    pub message: [BaseElement; 2],
}

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(&self.pub_key_root[..]);
        target.write_u32(self.num_pub_keys as u32);
        target.write_u32(self.num_signatures as u32);
        target.write(&self.message[..]);
    }
}

pub struct LamportThresholdAir {
    context: AirContext<BaseElement>,
    pub_key_root: [BaseElement; 2],
    num_pub_keys: usize,
    num_signatures: usize,
    message: [BaseElement; 2],
}

impl Air for LamportThresholdAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    #[rustfmt::skip]
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // define degrees for all transition constraints
        let degrees = vec![
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
            // merkle path verification
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(5, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]),
            // merkle path index
            TransitionConstraintDegree::with_cycles(2, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN]), // index bit is binary
            TransitionConstraintDegree::with_cycles(1, vec![HASH_CYCLE_LEN, SIG_CYCLE_LEN, SIG_CYCLE_LEN]), // index accumulator
            // signature count
            TransitionConstraintDegree::with_cycles(2, vec![SIG_CYCLE_LEN]), // sig flag is binary
            TransitionConstraintDegree::with_cycles(1, vec![SIG_CYCLE_LEN]), // sig counter
            TransitionConstraintDegree::with_cycles(2, vec![SIG_CYCLE_LEN]),
            TransitionConstraintDegree::with_cycles(2, vec![SIG_CYCLE_LEN]),
        ];
        assert_eq!(TRACE_WIDTH, trace_info.width());
        LamportThresholdAir {
            context: AirContext::new(trace_info, degrees, 26, options),
            pub_key_root: pub_inputs.pub_key_root,
            num_pub_keys: pub_inputs.num_pub_keys,
            num_signatures: pub_inputs.num_signatures,
            message: pub_inputs.message,
        }
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
        let m0_bit = periodic_values[2];
        let m1_bit = periodic_values[3];
        let hash_flag = periodic_values[4];
        let ark = &periodic_values[5..];

        // evaluate the constraints
        evaluate_constraints(
            result,
            current,
            next,
            ark,
            hash_flag,
            sig_cycle_end_flag,
            m0_bit,
            m1_bit,
            power_of_two,
        );
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // ----- assertions against the first step of every cycle: 0, 1024, 2048 etc. -------------
        let mut assertions = vec![
            // for private key hasher, last 4 state register should be set to zeros
            Assertion::periodic(2, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(3, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(4, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(5, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(8, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(9, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(10, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(11, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            // for public key hasher, all registers should be set to zeros
            Assertion::periodic(12, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(13, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(14, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(15, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(16, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(17, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            // for merkle path verification, last 4 registers should be set to zeros
            Assertion::periodic(20, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(21, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(22, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            Assertion::periodic(23, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
            // merkle path index accumulator should be initialized to zero
            Assertion::periodic(25, 0, SIG_CYCLE_LEN, BaseElement::ZERO),
        ];

        // ----- assertions against the step in every cycle when the Merkle path computation ends -
        // these steps depend on the depth of the public key Merkle tree; for example, if the Merkle
        // tree has 4 elements, then the steps are: 24, 1048, 2072, 3096
        let num_cycles = self.num_pub_keys.next_power_of_two();
        let merkle_root_offset = (log2(num_cycles) + 1) as usize * HASH_CYCLE_LEN;

        // distinct key indexes should be used; the sequence starts at the last index of the tree
        // (to pad the first cycle) and then wraps around and proceeds with index 0, 1, 2 etc.
        let index_list = get_index_list(num_cycles);

        assertions.extend_from_slice(&[
            Assertion::sequence(25, merkle_root_offset, SIG_CYCLE_LEN, index_list),
            // merkle path verifications should terminate with the root public key
            Assertion::periodic(18, merkle_root_offset, SIG_CYCLE_LEN, self.pub_key_root[0]),
            Assertion::periodic(19, merkle_root_offset, SIG_CYCLE_LEN, self.pub_key_root[1]),
        ]);

        // ----- assertions for the entire execution trace -----------------------------------------

        let last_step = self.trace_length() - 1;
        assertions.extend_from_slice(&[
            // signature counter starts at zero and terminates with the expected count of signatures
            Assertion::single(27, 0, BaseElement::ZERO),
            Assertion::single(27, last_step, BaseElement::from(self.num_signatures as u64)),
            // the first public key for merkle path verification should be a zero key (it is only
            // used for padding)
            Assertion::single(18, 0, BaseElement::ZERO),
            Assertion::single(19, 0, BaseElement::ZERO),
        ]);
        assertions
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

        // build message bit columns m0 and m1
        let m0 = self.message[0].as_int();
        let m1 = self.message[1].as_int();
        let mut m0_bits = Vec::with_capacity(SIG_CYCLE_LEN);
        let mut m1_bits = Vec::with_capacity(SIG_CYCLE_LEN);
        for i in 0..SIG_CYCLE_LEN {
            let cycle_num = i / HASH_CYCLE_LEN;
            m0_bits.push(BaseElement::from((m0 >> cycle_num) & 1));
            m1_bits.push(BaseElement::from((m1 >> cycle_num) & 1));
        }
        result.push(m0_bits);
        result.push(m1_bits);

        // add hash cycle mask (seven ones followed by a zero), and rescue round constants
        result.push(HASH_CYCLE_MASK.to_vec());
        result.append(&mut rescue::get_round_constants());

        result
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
fn evaluate_constraints<E: FieldElement + From<BaseElement>>(
    result: &mut [E],
    current: &[E],
    next: &[E],
    ark: &[E],
    hash_flag: E,
    sig_cycle_end_flag: E,
    m0_bit: E,
    m1_bit: E,
    power_of_two: E,
) {
    // when hash_flag = 1 (which happens on all steps except steps which are one less than a
    // multiple of 8 - e.g. all steps except for 7, 15, 23 etc.), and we are not on the last step
    // of a signature cycle make sure the contents of registers 24 and 25 are copied over, and
    // for other registers, Rescue constraints are applied separately for hashing secret and
    // public keys
    let flag = not(sig_cycle_end_flag) * hash_flag;
    rescue::enforce_round(&mut result[..6],  &current[..6],  &next[..6],  ark, flag);
    rescue::enforce_round(&mut result[6..12], &current[6..12], &next[6..12], ark, flag);
    rescue::enforce_round(&mut result[12..18], &current[12..18], &next[12..18], ark, flag);
    rescue::enforce_round(&mut result[18..24], &current[18..24], &next[18..24], ark, flag);
    result.agg_constraint(24, flag, are_equal(current[24], next[24]));
    result.agg_constraint(25, flag, are_equal(current[25], next[25]));
    
    // when hash_flag = 0 (which happens on steps which are one less than a multiple of 8 - e.g. 7,
    // 15, 23 etc.), and we are not on the last step of a signature cycle:
    let flag = not(sig_cycle_end_flag) * not(hash_flag);
    // registers 2..6 and 8..12 were set to zeros
    result.agg_constraint(0, flag, is_zero(next[2]));
    result.agg_constraint(1, flag, is_zero(next[3]));
    result.agg_constraint(2, flag, is_zero(next[4]));
    result.agg_constraint(3, flag, is_zero(next[5]));
    result.agg_constraint(4, flag, is_zero(next[8]));
    result.agg_constraint(5, flag, is_zero(next[9]));
    result.agg_constraint(6, flag, is_zero(next[10]));
    result.agg_constraint(7, flag, is_zero(next[11]));

    // contents of registers 16 and 17 (capacity section of public key hasher state) were
    // copied over to the next step
    result.agg_constraint(8, flag, are_equal(current[16], next[16]));
    result.agg_constraint(9, flag, are_equal(current[17], next[17]));

    // when current bit of m0 = 1, hash of private key 1 (which should be equal to public key)
    // should be injected into the hasher state for public key aggregator
    result.agg_constraint(10, flag * m0_bit,are_equal(current[12] + current[0], next[12]));
    result.agg_constraint(11, flag * m0_bit, are_equal(current[13] + current[1], next[13]));

    // when current bit of m1 = 1, hash of private key 2 (which should be equal to public key)
    // should be injected into the hasher state for public key aggregator
    result.agg_constraint(16, flag * m1_bit, are_equal(current[14] + current[6], next[14]));
    result.agg_constraint(17, flag * m1_bit, are_equal(current[15] + current[7], next[15]));

    // when merkle path bit = 1, next values for registers 18 and 19 should come from
    // registers 20 and 21; but when the bit = 0, values should be copied over from 
    // registers 18 and 19; registers 22 and 23 should be reset to zeros.
    let mp_bit = current[24];
    result.agg_constraint(18, flag * not(mp_bit), are_equal(current[18], next[18]));
    result.agg_constraint(19, flag * not(mp_bit), are_equal(current[19], next[19]));
    result.agg_constraint(20, flag * mp_bit, are_equal(current[18], next[20]));
    result.agg_constraint(21, flag * mp_bit, are_equal(current[19], next[21]));
    result.agg_constraint(22, flag, is_zero(next[22]));
    result.agg_constraint(23, flag, is_zero(next[23]));

    // make sure merkle path index bit is binary
    result.agg_constraint(24, flag, is_binary(current[24]));
    // make sure merkle path index aggregator is incremented correctly
    let next_index_agg = current[25] + current[24] * power_of_two;
    result.agg_constraint(25, flag, are_equal(next_index_agg, next[25]));

    // sig flag should be binary and shouldn't change during the signature cycle
    let sig_flag = current[26];
    result.agg_constraint(26, not(sig_cycle_end_flag), are_equal(sig_flag, next[26]));
    result.agg_constraint(26, sig_cycle_end_flag, is_binary(sig_flag));

    // on all steps but the last step of the signature cycle, sig count should be copied
    // over to the next step; on the last step of the signature cycle the next value of 
    // sig count should be set to the previous value, plus the current value of sig flag
    result.agg_constraint(27, not(sig_cycle_end_flag), are_equal(current[27], next[27]));
    result.agg_constraint(27, sig_cycle_end_flag, are_equal(current[27] + sig_flag, next[27]));

    // when sig_count=1, public key computed during signature verification (registers 12 and 13)
    // should be copied to the beginning of Merkle path computation for the aggregated public key
    // (registers 18 and 19); this constraint should be enforced only on the last step of signature
    // verification cycle
    result.agg_constraint(28, sig_cycle_end_flag * sig_flag, are_equal(current[12], next[18]));
    result.agg_constraint(29, sig_cycle_end_flag * sig_flag, are_equal(current[13], next[19]));
}

fn get_index_list(num_keys: usize) -> Vec<BaseElement> {
    let mut result = Vec::with_capacity(num_keys);
    result.push(BaseElement::from((num_keys - 1) as u64));
    for i in 0..(num_keys - 1) {
        result.push(BaseElement::from(i as u64));
    }
    result
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
