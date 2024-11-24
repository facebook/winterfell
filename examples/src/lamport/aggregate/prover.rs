// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;
use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use super::{
    get_power_series, rescue, BaseElement, DefaultRandomCoin, ElementHasher, FieldElement,
    LamportAggregateAir, PhantomData, ProofOptions, Prover, PublicInputs, Signature, StarkField,
    CYCLE_LENGTH, NUM_HASH_ROUNDS, SIG_CYCLE_LENGTH, TRACE_WIDTH,
};

// CONSTANTS
// ================================================================================================

const TWO: BaseElement = BaseElement::new(2);
const ZERO_KEY: [BaseElement; 2] = [BaseElement::ZERO, BaseElement::ZERO];

// TYPES AND INTERFACES
// ================================================================================================

struct SignatureInfo {
    m0: u128,
    m1: u128,
    key_schedule: KeySchedule,
}

struct KeySchedule {
    sec_keys1: Vec<[BaseElement; 2]>,
    sec_keys2: Vec<[BaseElement; 2]>,
    pub_keys1: Vec<[BaseElement; 2]>,
    pub_keys2: Vec<[BaseElement; 2]>,
}

// LAMPORT PROVER
// ================================================================================================

pub struct LamportAggregateProver<H: ElementHasher> {
    pub_inputs: PublicInputs,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> LamportAggregateProver<H> {
    pub fn new(
        pub_keys: &[[BaseElement; 2]],
        messages: &[[BaseElement; 2]],
        options: ProofOptions,
    ) -> Self {
        let pub_inputs = PublicInputs {
            pub_keys: pub_keys.to_vec(),
            messages: messages.to_vec(),
        };
        Self {
            pub_inputs,
            options,
            _hasher: PhantomData,
        }
    }

    pub fn build_trace(
        &self,
        messages: &[[BaseElement; 2]],
        signatures: &[Signature],
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let trace_length = SIG_CYCLE_LENGTH * messages.len();
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        let powers_of_two = get_power_series(TWO, 128);

        trace.fragments(SIG_CYCLE_LENGTH).for_each(|mut sig_trace| {
            let i = sig_trace.index();
            let sig_info = build_sig_info(&messages[i], &signatures[i]);
            sig_trace.fill(
                |state| {
                    init_sig_verification_state(&sig_info, state);
                },
                |step, state| {
                    update_sig_verification_state(step, &sig_info, &powers_of_two, state);
                },
            );
        });

        trace
    }
}

impl<H: ElementHasher> Prover for LamportAggregateProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = LamportAggregateAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// TRACE INITIALIZATION
// ================================================================================================

fn init_sig_verification_state(sig_info: &SignatureInfo, state: &mut [BaseElement]) {
    // message accumulators
    state[0] = BaseElement::new(sig_info.m0 & 1); // m0 bits
    state[1] = BaseElement::new(sig_info.m1 & 1); // m1 bits
    state[2] = BaseElement::ZERO; // m0 accumulator
    state[3] = BaseElement::ZERO; // m1 accumulator

    // secret key 1 hashing
    state[4] = sig_info.key_schedule.sec_keys1[0][0];
    state[5] = sig_info.key_schedule.sec_keys1[0][1];
    state[6] = BaseElement::ZERO;
    state[7] = BaseElement::ZERO;
    state[8] = BaseElement::ZERO; // capacity
    state[9] = BaseElement::ZERO; // capacity

    // secret key 2 hashing
    state[10] = sig_info.key_schedule.sec_keys2[0][0];
    state[11] = sig_info.key_schedule.sec_keys2[0][1];
    state[12] = BaseElement::ZERO;
    state[13] = BaseElement::ZERO;
    state[14] = BaseElement::ZERO; // capacity
    state[15] = BaseElement::ZERO; // capacity

    // public key hashing
    state[16] = BaseElement::ZERO;
    state[17] = BaseElement::ZERO;
    state[18] = BaseElement::ZERO;
    state[19] = BaseElement::ZERO;
    state[20] = BaseElement::ZERO; // capacity
    state[21] = BaseElement::ZERO; // capacity
}

// TRANSITION FUNCTION
// ================================================================================================

fn update_sig_verification_state(
    step: usize,
    sig_info: &SignatureInfo,
    powers_of_two: &[BaseElement],
    state: &mut [BaseElement],
) {
    // determine which cycle we are in and also where in the cycle we are
    let cycle_num = step / CYCLE_LENGTH;
    let cycle_step = step % CYCLE_LENGTH;

    // break the state into logical parts
    let (msg_acc_state, rest) = state.split_at_mut(4);
    let (sec_key_1_hash, rest) = rest.split_at_mut(6);
    let (sec_key_2_hash, pub_key_hash) = rest.split_at_mut(6);

    if cycle_step < NUM_HASH_ROUNDS {
        // for the first 7 steps in each cycle apply Rescue round function to
        // registers where keys are hashed; all other registers retain their values
        rescue::apply_round(sec_key_1_hash, cycle_step);
        rescue::apply_round(sec_key_2_hash, cycle_step);
        rescue::apply_round(pub_key_hash, cycle_step);
    } else {
        let m0_bit = msg_acc_state[0];
        let m1_bit = msg_acc_state[1];

        // copy next set of public keys into the registers computing hash of the public key
        update_pub_key_hash(
            pub_key_hash,
            m0_bit,
            m1_bit,
            sec_key_1_hash,
            sec_key_2_hash,
            &sig_info.key_schedule.pub_keys1[cycle_num],
            &sig_info.key_schedule.pub_keys2[cycle_num],
        );

        // copy next set of private keys into the registers computing private key hashes
        init_hash_state(sec_key_1_hash, &sig_info.key_schedule.sec_keys1[cycle_num + 1]);
        init_hash_state(sec_key_2_hash, &sig_info.key_schedule.sec_keys2[cycle_num + 1]);

        // update message accumulator with the next set of message bits
        apply_message_acc(
            msg_acc_state,
            sig_info.m0,
            sig_info.m1,
            cycle_num,
            powers_of_two[cycle_num],
        );
    }
}

fn apply_message_acc(
    state: &mut [BaseElement],
    m0: u128,
    m1: u128,
    cycle_num: usize,
    power_of_two: BaseElement,
) {
    let m0_bit = state[0];
    let m1_bit = state[1];

    state[0] = BaseElement::new((m0 >> (cycle_num + 1)) & 1);
    state[1] = BaseElement::new((m1 >> (cycle_num + 1)) & 1);
    state[2] += power_of_two * m0_bit;
    state[3] += power_of_two * m1_bit;
}

fn init_hash_state(state: &mut [BaseElement], values: &[BaseElement; 2]) {
    state[0] = values[0];
    state[1] = values[1];
    state[2] = BaseElement::ZERO;
    state[3] = BaseElement::ZERO;
    state[4] = BaseElement::ZERO;
    state[5] = BaseElement::ZERO;
}

fn update_pub_key_hash(
    state: &mut [BaseElement],
    m0_bit: BaseElement,
    m1_bit: BaseElement,
    sec_key1_hash: &[BaseElement],
    sec_key2_hash: &[BaseElement],
    pub_key1: &[BaseElement],
    pub_key2: &[BaseElement],
) {
    if m0_bit == FieldElement::ONE {
        state[0] += sec_key1_hash[0];
        state[1] += sec_key1_hash[1];
    } else {
        state[0] += pub_key1[0];
        state[1] += pub_key1[1];
    }

    if m1_bit == FieldElement::ONE {
        state[2] += sec_key2_hash[0];
        state[3] += sec_key2_hash[1];
    } else {
        state[2] += pub_key2[0];
        state[3] += pub_key2[1];
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_sig_info(msg: &[BaseElement; 2], sig: &Signature) -> SignatureInfo {
    let m0 = msg[0].as_int();
    let m1 = msg[1].as_int();
    let key_schedule = build_key_schedule(m0, m1, sig);
    SignatureInfo { m0, m1, key_schedule }
}

/// Transforms signature into 4 vectors of keys such that keys 0..127 and 127..254 end up in
/// different vectors; keys that are missing from the signature are replaced with a zeros.
fn build_key_schedule(m0: u128, m1: u128, sig: &Signature) -> KeySchedule {
    let mut n_ones = 0;
    let mut n_zeros = 0;
    let mut result = KeySchedule {
        sec_keys1: vec![ZERO_KEY; 128],
        sec_keys2: vec![ZERO_KEY; 128],
        pub_keys1: vec![ZERO_KEY; 128],
        pub_keys2: vec![ZERO_KEY; 128],
    };

    for i in 0..127 {
        if (m0 >> i) & 1 == 1 {
            result.sec_keys1[i] = sig.ones[n_ones];
            n_ones += 1;
        } else {
            result.pub_keys1[i] = sig.zeros[n_zeros];
            n_zeros += 1;
        }
    }

    for i in 0..127 {
        if (m1 >> i) & 1 == 1 {
            result.sec_keys2[i] = sig.ones[n_ones];
            n_ones += 1;
        } else {
            result.pub_keys2[i] = sig.zeros[n_zeros];
            n_zeros += 1;
        }
    }

    result
}
