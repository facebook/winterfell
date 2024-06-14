// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;
use std::time::Instant;

use rand_utils::rand_array;
use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, ExtensionOf, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{Blake3_192, Blake3_256, Example, ExampleOptions, HashFunction, Sha3_256};

mod custom_trace_table;
pub use custom_trace_table::RapTraceTable;

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

pub fn get_example(
    options: &ExampleOptions,
    chain_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(42, 4);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(RescueRapsExample::<Blake3_192>::new(chain_length, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(RescueRapsExample::<Blake3_256>::new(chain_length, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(RescueRapsExample::<Sha3_256>::new(chain_length, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct RescueRapsExample<H: ElementHasher> {
    options: ProofOptions,
    chain_length: usize,
    seeds: Vec<[BaseElement; 2]>,
    permuted_seeds: Vec<[BaseElement; 2]>,
    result: [[BaseElement; 2]; 2],
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> RescueRapsExample<H> {
    pub fn new(chain_length: usize, options: ProofOptions) -> Self {
        assert!(chain_length.is_power_of_two(), "chain length must a power of 2");
        assert!(chain_length > 2, "chain length must be at least 4");

        let mut seeds = vec![[BaseElement::ZERO; 2]; chain_length];
        for internal_seed in seeds.iter_mut() {
            *internal_seed = rand_array();
        }
        let mut permuted_seeds = seeds[2..].to_vec();
        permuted_seeds.push(seeds[0]);
        permuted_seeds.push(seeds[1]);

        // compute the sequence of hashes using external implementation of Rescue hash
        let now = Instant::now();
        let result = compute_permuted_hash_chains(&seeds, &permuted_seeds);
        println!(
            "Computed two permuted chains of {} Rescue hashes in {} ms",
            chain_length,
            now.elapsed().as_millis(),
        );

        RescueRapsExample {
            options,
            chain_length,
            seeds,
            permuted_seeds,
            result,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for RescueRapsExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // generate the execution trace
        println!("Generating proof for computing a chain of {} Rescue hashes", self.chain_length);

        // create a prover
        let prover = RescueRapsProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace(&self.seeds, &self.permuted_seeds, self.result);
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { result: self.result };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<RescueRapsAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs { result: [self.result[1], self.result[0]] };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<RescueRapsAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn absorb(state: &mut [BaseElement; STATE_WIDTH], values: &[BaseElement; 2]) {
    state[0] += values[0];
    state[1] += values[1];
    for i in 0..NUM_HASH_ROUNDS {
        rescue::apply_round(state, i);
    }
}

fn compute_permuted_hash_chains(
    seeds: &[[BaseElement; 2]],
    permuted_seeds: &[[BaseElement; 2]],
) -> [[BaseElement; 2]; 2] {
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    let mut permuted_state = [BaseElement::ZERO; STATE_WIDTH];

    // Start the hash chain
    for (seed, permuted_seed) in seeds.iter().zip(permuted_seeds) {
        absorb(&mut state, seed);
        absorb(&mut permuted_state, permuted_seed);
    }

    [[state[0], state[1]], [permuted_state[0], permuted_state[1]]]
}

fn apply_rescue_round_parallel(multi_state: &mut [BaseElement], step: usize) {
    debug_assert_eq!(multi_state.len() % STATE_WIDTH, 0);

    for state in multi_state.chunks_mut(STATE_WIDTH) {
        rescue::apply_round(state, step)
    }
}
