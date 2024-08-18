// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;
use std::time::Instant;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{Blake3_192, Blake3_256, Example, ExampleOptions, HashFunction, Sha3_256};

#[allow(clippy::module_inception)]
pub(crate) mod rescue;

mod air;
use air::{PublicInputs, RescueAir};

mod prover;
use prover::RescueProver;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const CYCLE_LENGTH: usize = 16;
const NUM_HASH_ROUNDS: usize = 14;
const TRACE_WIDTH: usize = 4;

// RESCUE HASH CHAIN EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    chain_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(42, 4);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(RescueExample::<Blake3_192>::new(chain_length, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(RescueExample::<Blake3_256>::new(chain_length, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(RescueExample::<Sha3_256>::new(chain_length, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct RescueExample<H: ElementHasher> {
    options: ProofOptions,
    chain_length: usize,
    seed: [BaseElement; 2],
    result: [BaseElement; 2],
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RescueExample<H> {
    pub fn new(chain_length: usize, options: ProofOptions) -> Self {
        assert!(chain_length.is_power_of_two(), "chain length must a power of 2");
        let seed = [BaseElement::from(42u8), BaseElement::from(43u8)];

        // compute the sequence of hashes using external implementation of Rescue hash
        let now = Instant::now();
        let result = compute_hash_chain(seed, chain_length);
        println!(
            "Computed a chain of {} Rescue hashes in {} ms",
            chain_length,
            now.elapsed().as_millis(),
        );

        RescueExample {
            options,
            chain_length,
            seed,
            result,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for RescueExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // generate the execution trace
        println!("Generating proof for computing a chain of {} Rescue hashes", self.chain_length);

        // create a prover
        let prover = RescueProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace(self.seed, self.chain_length);
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { seed: self.seed, result: self.result };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<RescueAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            seed: self.seed,
            result: [self.result[0], self.result[1] + BaseElement::ONE],
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<RescueAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
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
