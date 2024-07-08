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
    message_to_elements, rescue, Example, PrivateKey, Signature, CYCLE_LENGTH, NUM_HASH_ROUNDS,
};
use crate::{Blake3_192, Blake3_256, ExampleOptions, HashFunction, Sha3_256};

mod air;
use air::{LamportAggregateAir, PublicInputs};

mod prover;
use prover::LamportAggregateProver;

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 22;
const SIG_CYCLE_LENGTH: usize = 128 * CYCLE_LENGTH; // 1024 steps

// LAMPORT MULTI-MESSAGE, MULTI-KEY, SIGNATURE EXAMPLE
// ================================================================================================
pub fn get_example(
    options: &ExampleOptions,
    num_signatures: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(28, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(LamportAggregateExample::<Blake3_192>::new(num_signatures, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(LamportAggregateExample::<Blake3_256>::new(num_signatures, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(LamportAggregateExample::<Sha3_256>::new(num_signatures, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct LamportAggregateExample<H: ElementHasher> {
    options: ProofOptions,
    pub_keys: Vec<[BaseElement; 2]>,
    messages: Vec<[BaseElement; 2]>,
    signatures: Vec<Signature>,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> LamportAggregateExample<H> {
    pub fn new(num_signatures: usize, options: ProofOptions) -> Self {
        assert!(num_signatures.is_power_of_two(), "number of signatures must be a power of 2");
        // generate private/public key pairs for the specified number of signatures
        let mut private_keys = Vec::with_capacity(num_signatures);
        let mut public_keys = Vec::with_capacity(num_signatures);
        let now = Instant::now();
        for i in 0..num_signatures {
            private_keys.push(PrivateKey::from_seed([i as u8; 32]));
            public_keys.push(private_keys[i].pub_key().to_elements());
        }
        println!(
            "Generated {} private-public key pairs in {} ms",
            num_signatures,
            now.elapsed().as_millis()
        );

        // sign messages
        let now = Instant::now();
        let mut signatures = Vec::new();
        let mut messages = Vec::new();
        for (i, private_key) in private_keys.iter().enumerate() {
            let msg = format!("test message {i}");
            signatures.push(private_key.sign(msg.as_bytes()));
            messages.push(message_to_elements(msg.as_bytes()));
        }
        println!("Signed {} messages in {} ms", num_signatures, now.elapsed().as_millis());

        // verify signature
        let now = Instant::now();
        let mut pub_keys = Vec::new();
        for (i, signature) in signatures.iter().enumerate() {
            let pk = private_keys[i].pub_key();
            pub_keys.push(pk.to_elements());
            let msg = format!("test message {i}");
            assert!(pk.verify(msg.as_bytes(), signature));
        }
        println!("Verified {} signature in {} ms", num_signatures, now.elapsed().as_millis());

        LamportAggregateExample {
            options,
            pub_keys,
            messages,
            signatures,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for LamportAggregateExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // generate the execution trace
        println!("Generating proof for verifying {} Lamport+ signatures", self.signatures.len());

        // create a prover
        let prover =
            LamportAggregateProver::<H>::new(&self.pub_keys, &self.messages, self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace(&self.messages, &self.signatures);
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            pub_keys: self.pub_keys.clone(),
            messages: self.messages.clone(),
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<LamportAggregateAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let mut pub_keys = self.pub_keys.clone();
        pub_keys.swap(0, 1);
        let pub_inputs = PublicInputs {
            pub_keys,
            messages: self.messages.clone(),
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<LamportAggregateAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}
