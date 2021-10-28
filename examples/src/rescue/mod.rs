// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{Example, ExampleOptions};
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    ProofOptions, StarkProof, VerifierError,
};

#[allow(clippy::module_inception)]
mod rescue;

mod air;
use air::{PublicInputs, RescueAir, RescueTraceBuilder};

#[cfg(test)]
mod tests;

// RESCUE HASH CHAIN EXAMPLE
// ================================================================================================

pub fn get_example(options: ExampleOptions, chain_length: usize) -> Box<dyn Example> {
    Box::new(RescueExample::new(
        chain_length,
        options.to_proof_options(42, 4),
    ))
}

pub struct RescueExample {
    options: ProofOptions,
    chain_length: usize,
    seed: [BaseElement; 2],
    result: [BaseElement; 2],
}

impl RescueExample {
    pub fn new(chain_length: usize, options: ProofOptions) -> RescueExample {
        assert!(
            chain_length.is_power_of_two(),
            "chain length must a power of 2"
        );
        let seed = [BaseElement::from(42u8), BaseElement::from(43u8)];

        // compute the sequence of hashes using external implementation of Rescue hash
        let now = Instant::now();
        let result = compute_hash_chain(seed, chain_length);
        debug!(
            "Computed a chain of {} Rescue hashes in {} ms",
            chain_length,
            now.elapsed().as_millis(),
        );

        RescueExample {
            options,
            chain_length,
            seed,
            result,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for RescueExample {
    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for computing a chain of {} Rescue hashes\n\
            ---------------------",
            self.chain_length
        );

        // instantiate trace builder
        let trace_builder = RescueTraceBuilder::new(self.seed, self.chain_length);

        // generate the proof
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: self.result,
        };
        winterfell::prove::<RescueAir, RescueTraceBuilder>(
            trace_builder,
            pub_inputs,
            self.options.clone(),
        )
        .unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: self.result,
        };
        winterfell::verify::<RescueAir>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: [self.result[0], self.result[1] + BaseElement::ONE],
        };
        winterfell::verify::<RescueAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn compute_hash_chain(seed: [BaseElement; 2], length: usize) -> [BaseElement; 2] {
    let mut values = seed;
    let mut result = [BaseElement::ZERO; 2];
    for _ in 0..length {
        rescue::hash(values, &mut result);
        values.copy_from_slice(&result);
    }
    result
}
