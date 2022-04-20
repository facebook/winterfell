// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{Example, ExampleOptions};
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, log2, ExtensionOf, FieldElement},
    ProofOptions, Prover, StarkProof, Trace, VerifierError,
};

mod custom_trace_table;
use custom_trace_table::RapTraceTable;

use super::rescue::rescue::{self, STATE_WIDTH};

mod air;
use air::{PublicInputs, RescueRapsAir};

mod prover;
use prover::RescueRapsProver;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const CYCLE_LENGTH: usize = 16;
const NUM_HASH_ROUNDS: usize = 14;
const TRACE_WIDTH: usize = 4 * 2;

// RESCUE SPLIT HASH CHAIN EXAMPLE
// ================================================================================================

pub fn get_example(options: ExampleOptions, chain_length: usize) -> Box<dyn Example> {
    Box::new(RescueRapsExample::new(
        chain_length,
        options.to_proof_options(42, 4),
    ))
}

pub struct RescueRapsExample {
    options: ProofOptions,
    chain_length: usize,
    seed: [BaseElement; 2],
    // Store the temporary hash chain in the middle
    // of the execution and the final hash digest.
    result: ([BaseElement; 2], [BaseElement; 2]),
}

impl RescueRapsExample {
    pub fn new(chain_length: usize, options: ProofOptions) -> RescueRapsExample {
        assert!(
            chain_length.is_power_of_two(),
            "chain length must a power of 2"
        );
        let seed = [BaseElement::from(42u8), BaseElement::from(43u8)];

        // compute the sequence of hashes using external implementation of Rescue hash
        let now = Instant::now();
        let result = compute_split_hash_chain(seed, chain_length / 2);
        debug!(
            "Computed a chain of {} Rescue hashes in {} ms",
            chain_length,
            now.elapsed().as_millis(),
        );

        RescueRapsExample {
            options,
            chain_length,
            seed,
            result,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for RescueRapsExample {
    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for computing a chain of {} Rescue hashes\n\
            ---------------------",
            self.chain_length
        );

        // create a prover
        let prover = RescueRapsProver::new(self.options.clone());

        // generate the execution trace
        let now = Instant::now();
        let trace = prover.build_trace(self.seed, self.result, self.chain_length / 2);
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
            seed: self.seed,
            result: self.result.1,
        };
        winterfell::verify::<RescueRapsAir>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: [self.result.1[0], self.result.1[1] + BaseElement::ONE],
        };
        winterfell::verify::<RescueRapsAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn compute_split_hash_chain(
    seed: [BaseElement; 2],
    length: usize,
) -> ([BaseElement; 2], [BaseElement; 2]) {
    let mut values = seed;
    let mut tmp = [BaseElement::ZERO; 2];
    let mut result = ([BaseElement::ZERO; 2], [BaseElement::ZERO; 2]);

    // Start the hash chain
    for _ in 0..length {
        rescue::hash(values, &mut tmp);
        values.copy_from_slice(&tmp);
    }
    // Store the intermediary value
    result.0 = [tmp[0], tmp[1]];

    // Continue the hash chain
    for _ in 0..length {
        rescue::hash(values, &mut tmp);
        values.copy_from_slice(&tmp);
    }
    // Store the final value
    result.1 = tmp;

    result
}
