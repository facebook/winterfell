// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    message_to_elements, rescue, Example, PrivateKey, Signature, CYCLE_LENGTH, NUM_HASH_ROUNDS,
};
use crate::ExampleOptions;
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, get_power_series, log2, FieldElement, StarkField},
    ProofOptions, Prover, StarkProof, Trace, TraceTable, VerifierError,
};

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
pub fn get_example(options: ExampleOptions, num_signatures: usize) -> Box<dyn Example> {
    Box::new(LamportAggregateExample::new(
        num_signatures,
        options.to_proof_options(28, 8),
    ))
}

pub struct LamportAggregateExample {
    options: ProofOptions,
    pub_keys: Vec<[BaseElement; 2]>,
    messages: Vec<[BaseElement; 2]>,
    signatures: Vec<Signature>,
}

impl LamportAggregateExample {
    pub fn new(num_signatures: usize, options: ProofOptions) -> Self {
        assert!(
            num_signatures.is_power_of_two(),
            "number of signatures must be a power of 2"
        );
        // generate private/public key pairs for the specified number of signatures
        let mut private_keys = Vec::with_capacity(num_signatures);
        let mut public_keys = Vec::with_capacity(num_signatures);
        let now = Instant::now();
        for i in 0..num_signatures {
            private_keys.push(PrivateKey::from_seed([i as u8; 32]));
            public_keys.push(private_keys[i].pub_key().to_elements());
        }
        debug!(
            "Generated {} private-public key pairs in {} ms",
            num_signatures,
            now.elapsed().as_millis()
        );

        // sign messages
        let now = Instant::now();
        let mut signatures = Vec::new();
        let mut messages = Vec::new();
        for (i, private_key) in private_keys.iter().enumerate() {
            let msg = format!("test message {}", i);
            signatures.push(private_key.sign(msg.as_bytes()));
            messages.push(message_to_elements(msg.as_bytes()));
        }
        debug!(
            "Signed {} messages in {} ms",
            num_signatures,
            now.elapsed().as_millis()
        );

        // verify signature
        let now = Instant::now();
        let mut pub_keys = Vec::new();
        for (i, signature) in signatures.iter().enumerate() {
            let pk = private_keys[i].pub_key();
            pub_keys.push(pk.to_elements());
            let msg = format!("test message {}", i);
            assert!(pk.verify(msg.as_bytes(), signature));
        }
        debug!(
            "Verified {} signature in {} ms",
            num_signatures,
            now.elapsed().as_millis()
        );

        LamportAggregateExample {
            options,
            pub_keys,
            messages,
            signatures,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for LamportAggregateExample {
    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for verifying {} Lamport+ signatures \n\
            ---------------------",
            self.signatures.len(),
        );

        // create a prover
        let prover =
            LamportAggregateProver::new(&self.pub_keys, &self.messages, self.options.clone());

        let now = Instant::now();
        let trace = prover.build_trace(&self.messages, &self.signatures);
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            pub_keys: self.pub_keys.clone(),
            messages: self.messages.clone(),
        };
        winterfell::verify::<LamportAggregateAir>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let mut pub_keys = self.pub_keys.clone();
        pub_keys.swap(0, 1);
        let pub_inputs = PublicInputs {
            pub_keys,
            messages: self.messages.clone(),
        };
        winterfell::verify::<LamportAggregateAir>(proof, pub_inputs)
    }
}
