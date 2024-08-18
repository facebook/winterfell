// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;
use std::time::Instant;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, get_power_series, FieldElement, StarkField},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use super::{
    message_to_elements, rescue, Example, PrivateKey, Signature, CYCLE_LENGTH as HASH_CYCLE_LENGTH,
    NUM_HASH_ROUNDS,
};
use crate::{Blake3_192, Blake3_256, ExampleOptions, HashFunction, Sha3_256};

mod signature;
use signature::AggPublicKey;

mod air;
use air::{LamportThresholdAir, PublicInputs};

mod prover;
use prover::LamportThresholdProver;

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 28;
const SIG_CYCLE_LENGTH: usize = 128 * HASH_CYCLE_LENGTH; // 1024 steps

// LAMPORT THRESHOLD SIGNATURE EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    num_signers: usize,
) -> Result<Box<dyn Example>, String> {
    let (_, hash_fn) = options.to_proof_options(28, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(LamportThresholdExample::<Blake3_192>::new(num_signers, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(LamportThresholdExample::<Blake3_256>::new(num_signers, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(LamportThresholdExample::<Sha3_256>::new(num_signers, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct LamportThresholdExample<H: ElementHasher> {
    options: ProofOptions,
    pub_key: AggPublicKey,
    signatures: Vec<(usize, Signature)>,
    message: [BaseElement; 2],
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> LamportThresholdExample<H> {
    pub fn new(num_signers: usize, options: &ExampleOptions) -> Self {
        assert!(
            (num_signers + 1).is_power_of_two(),
            "number of signers must be one less than a power of 2"
        );
        // generate private/public key pairs for the specified number of signatures
        let now = Instant::now();
        let private_keys = build_keys(num_signers);
        println!(
            "Generated {} private-public key pairs in {} ms",
            num_signers,
            now.elapsed().as_millis()
        );
        let public_keys = private_keys.iter().map(|k| k.pub_key()).collect();

        // sign the message with the subset of previously generated keys
        let message = "test message";
        let selected_indexes = pick_random_indexes(num_signers);
        let mut signatures = Vec::new();
        for &key_index in selected_indexes.iter() {
            let signature = private_keys[key_index].sign(message.as_bytes());
            signatures.push((key_index, signature));
        }

        // build the aggregated public key
        let now = Instant::now();
        let pub_key = AggPublicKey::new(public_keys);
        println!("Built aggregated public key in {} ms", now.elapsed().as_millis());

        let (options, _) = options.to_proof_options(28, 8);

        LamportThresholdExample {
            options,
            pub_key,
            signatures,
            message: message_to_elements(message.as_bytes()),
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for LamportThresholdExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // generate the execution trace
        println!(
            "Generating proof for verifying {}-of-{} signature",
            self.signatures.len(),
            self.pub_key.num_keys(),
        );

        // create a prover
        let prover = LamportThresholdProver::<H>::new(
            &self.pub_key,
            self.message,
            &self.signatures,
            self.options.clone(),
        );

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace(&self.pub_key, self.message, &self.signatures);
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            pub_key_root: self.pub_key.root().to_elements(),
            num_pub_keys: self.pub_key.num_keys(),
            num_signatures: self.signatures.len(),
            message: self.message,
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<LamportThresholdAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            pub_key_root: self.pub_key.root().to_elements(),
            num_pub_keys: self.pub_key.num_keys(),
            num_signatures: self.signatures.len() + 1,
            message: self.message,
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<LamportThresholdAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_keys(num_keys: usize) -> Vec<PrivateKey> {
    let mut result = Vec::with_capacity(num_keys);
    for i in 0..num_keys {
        result.push(PrivateKey::from_seed([i as u8; 32]));
    }
    result.sort_by_key(|k| k.pub_key());
    result
}

fn pick_random_indexes(num_keys: usize) -> Vec<usize> {
    let num_selected_keys = num_keys * 2 / 3;
    let mut result = Vec::with_capacity(num_selected_keys);
    // TODO: change to actual random selection
    for i in 0..num_selected_keys {
        result.push(i);
    }
    result
}
