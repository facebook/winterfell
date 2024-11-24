// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use std::collections::HashMap;

#[cfg(feature = "concurrent")]
use winterfell::iterators::*;
use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use super::{
    get_power_series, rescue, AggPublicKey, BaseElement, DefaultRandomCoin, ElementHasher,
    FieldElement, LamportThresholdAir, PhantomData, ProofOptions, Prover, PublicInputs, Signature,
    StarkField, HASH_CYCLE_LENGTH, NUM_HASH_ROUNDS, SIG_CYCLE_LENGTH, TRACE_WIDTH,
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
    pub_key: [BaseElement; 2],
    key_schedule: KeySchedule,
    key_index: u128,
    key_path: Vec<rescue::Hash>,
    sig_flag: BaseElement,
    sig_count: BaseElement,
}

struct KeySchedule {
    sec_keys1: Vec<[BaseElement; 2]>,
    sec_keys2: Vec<[BaseElement; 2]>,
    pub_keys1: Vec<[BaseElement; 2]>,
    pub_keys2: Vec<[BaseElement; 2]>,
}

// LAMPORT PROVER
// ================================================================================================

pub struct LamportThresholdProver<H: ElementHasher> {
    pub_inputs: PublicInputs,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> LamportThresholdProver<H> {
    pub fn new(
        pub_key: &AggPublicKey,
        message: [BaseElement; 2],
        signatures: &[(usize, Signature)],
        options: ProofOptions,
    ) -> Self {
        let pub_inputs = PublicInputs {
            pub_key_root: pub_key.root().to_elements(),
            num_pub_keys: pub_key.num_keys(),
            num_signatures: signatures.len(),
            message,
        };
        Self {
            pub_inputs,
            options,
            _hasher: PhantomData,
        }
    }

    pub fn build_trace(
        &self,
        pub_key: &AggPublicKey,
        message: [BaseElement; 2],
        signatures: &[(usize, Signature)],
    ) -> TraceTable<BaseElement> {
        // allocate memory to hold the trace table
        let num_cycles = pub_key.num_keys().next_power_of_two();
        let trace_length = SIG_CYCLE_LENGTH * num_cycles;
        let mut trace = TraceTable::new(TRACE_WIDTH, trace_length);

        let powers_of_two = get_power_series(TWO, 128);

        // transform a list of signatures into a hashmap; this way we can look up signature
        // by index of the corresponding public key
        let mut signature_map = HashMap::new();
        for (i, sig) in signatures {
            signature_map.insert(i, sig);
        }

        // build a map of signature indexes to the running sum of valid signatures
        let mut sig_count = vec![0];
        for i in 1..num_cycles {
            match signature_map.get(&(i - 1)) {
                Some(_) => sig_count.push(sig_count[i - 1] + 1),
                None => sig_count.push(sig_count[i - 1]),
            }
        }

        // create a dummy signature; this will be used in place of signatures for keys
        // which did not sign the message
        let zero_sig = Signature {
            ones: vec![[BaseElement::ZERO; 2]; 254],
            zeros: vec![[BaseElement::ZERO; 2]; 254],
        };

        // iterate over all leaves of the aggregated public key; and if a signature exists for the
        // corresponding individual public key, use it go generate signature verification trace;
        // otherwise, use zero signature;
        trace.fragments(SIG_CYCLE_LENGTH).for_each(|mut sig_trace| {
            let i = sig_trace.index();
            let sig_info = match signature_map.get(&i) {
                Some(sig) => build_sig_info(i, &message, sig, 1, pub_key, sig_count[i]),
                None => build_sig_info(i, &message, &zero_sig, 0, pub_key, sig_count[i]),
            };

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

impl<H: ElementHasher> Prover for LamportThresholdProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = LamportThresholdAir;
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
    // secret key 1 hashing
    state[0] = sig_info.key_schedule.sec_keys1[0][0];
    state[1] = sig_info.key_schedule.sec_keys1[0][1];
    state[2] = BaseElement::ZERO;
    state[3] = BaseElement::ZERO;
    state[4] = BaseElement::ZERO; // capacity
    state[5] = BaseElement::ZERO; // capacity
                                  // secret key 2 hashing
    state[6] = sig_info.key_schedule.sec_keys2[0][0];
    state[7] = sig_info.key_schedule.sec_keys2[0][1];
    state[8] = BaseElement::ZERO;
    state[9] = BaseElement::ZERO;
    state[10] = BaseElement::ZERO; // capacity
    state[11] = BaseElement::ZERO; // capacity
                                   // public key hashing
    state[12] = BaseElement::ZERO;
    state[13] = BaseElement::ZERO;
    state[14] = BaseElement::ZERO;
    state[15] = BaseElement::ZERO;
    state[16] = BaseElement::ZERO; // capacity
    state[17] = BaseElement::ZERO; // capacity
                                   // merkle path verification
    state[18] = sig_info.pub_key[0];
    state[19] = sig_info.pub_key[1];
    state[20] = BaseElement::ZERO;
    state[21] = BaseElement::ZERO;
    state[22] = BaseElement::ZERO; // capacity
    state[23] = BaseElement::ZERO; // capacity
    state[24] = BaseElement::new(sig_info.key_index & 1); // index bits
    state[25] = BaseElement::ZERO; // index accumulator
                                   // signature counter
    state[26] = sig_info.sig_flag; // signature flag
    state[27] = sig_info.sig_count; // signature count
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
    let cycle_num = (step % SIG_CYCLE_LENGTH) / HASH_CYCLE_LENGTH;
    let cycle_step = (step % SIG_CYCLE_LENGTH) % HASH_CYCLE_LENGTH;

    // break the state into logical parts; we don't need to do anything with sig_count part
    // because values for these registers are set in the initial state and don't change
    // during the cycle
    let (sec_key_1_hash, rest) = state.split_at_mut(6);
    let (sec_key_2_hash, rest) = rest.split_at_mut(6);
    let (pub_key_hash, rest) = rest.split_at_mut(6);
    let (merkle_path_hash, rest) = rest.split_at_mut(6);
    let (merkle_path_idx, _sig_count) = rest.split_at_mut(2);

    if cycle_step < NUM_HASH_ROUNDS {
        // for the first 7 steps in each hash cycle apply Rescue round function to
        // registers where keys are hashed; all other registers retain their values
        rescue::apply_round(sec_key_1_hash, cycle_step);
        rescue::apply_round(sec_key_2_hash, cycle_step);
        rescue::apply_round(pub_key_hash, cycle_step);
        rescue::apply_round(merkle_path_hash, cycle_step);
    } else {
        // for the 8th step of very cycle do the following:

        let m0_bit = BaseElement::new((sig_info.m0 >> cycle_num) & 1);
        let m1_bit = BaseElement::new((sig_info.m1 >> cycle_num) & 1);
        let mp_bit = merkle_path_idx[0];

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

        // update merkle path index accumulator with the next index bit
        update_merkle_path_index(
            merkle_path_idx,
            sig_info.key_index,
            cycle_num,
            powers_of_two[cycle_num],
        );
        // prepare Merkle path hashing registers for hashing of the next node
        update_merkle_path_hash(merkle_path_hash, mp_bit, cycle_num, &sig_info.key_path);
    }
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

fn update_merkle_path_hash(
    state: &mut [BaseElement],
    index_bit: BaseElement,
    cycle_num: usize,
    key_path: &[rescue::Hash],
) {
    let h1 = state[0];
    let h2 = state[1];
    let cycle_num = (cycle_num + 1) % key_path.len();
    let path_node = key_path[cycle_num].to_elements();
    if index_bit == BaseElement::ONE {
        state[0] = path_node[0];
        state[1] = path_node[1];
        state[2] = h1;
        state[3] = h2;
    } else {
        state[0] = h1;
        state[1] = h2;
        state[2] = path_node[0];
        state[3] = path_node[1];
    }
    state[4] = BaseElement::ZERO;
    state[5] = BaseElement::ZERO;
}

fn update_merkle_path_index(
    state: &mut [BaseElement],
    index: u128,
    cycle_num: usize,
    power_of_two: BaseElement,
) {
    let index_bit = state[0];
    // the cycle is offset by +1 because the first node in the Merkle path is redundant and we
    // get it by hashing the public key
    state[0] = BaseElement::new((index >> (cycle_num + 1)) & 1);
    state[1] += power_of_two * index_bit;
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_sig_info(
    index: usize,
    msg: &[BaseElement; 2],
    sig: &Signature,
    sig_flag: u64,
    pub_key: &AggPublicKey,
    sig_count: u64,
) -> SignatureInfo {
    let m0 = msg[0].as_int();
    let m1 = msg[1].as_int();
    // we verify that the individual public key exists in the aggregated public key after
    // we've verified the signature; thus, the key index is offset by 1. That is, when
    // we verify signature for pub key 1, we verify Merkle path for pub key 0; the last
    // verification wraps around, but we don't care since the last signature is always a
    // zero signature which does not affect the count.
    let key_index = sig_index_to_key_index(index, pub_key.num_leaves());
    SignatureInfo {
        m0,
        m1,
        pub_key: pub_key.get_key(key_index).unwrap_or_default().to_elements(),
        key_schedule: build_key_schedule(m0, m1, sig),
        key_index: key_index as u128,
        key_path: pub_key.get_leaf_path(key_index),
        sig_flag: BaseElement::from(sig_flag),
        sig_count: BaseElement::from(sig_count),
    }
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

fn sig_index_to_key_index(sig_index: usize, num_cycles: usize) -> usize {
    if sig_index == 0 {
        num_cycles - 1
    } else {
        sig_index - 1
    }
}
