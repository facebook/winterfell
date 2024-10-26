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

mod air;
use air::{VdfAir, VdfInputs};

mod prover;
use prover::VdfProver;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const ALPHA: u64 = 3;
const INV_ALPHA: u128 = 226854911280625642308916371969163307691;
const FORTY_TWO: BaseElement = BaseElement::new(42);
const TRACE_WIDTH: usize = 1;

// VDF EXAMPLE
// ================================================================================================

pub fn get_example(options: &ExampleOptions, num_steps: usize) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(85, 2);

    match hash_fn {
        HashFunction::Blake3_192 => Ok(Box::new(VdfExample::<Blake3_192>::new(num_steps, options))),
        HashFunction::Blake3_256 => Ok(Box::new(VdfExample::<Blake3_256>::new(num_steps, options))),
        HashFunction::Sha3_256 => Ok(Box::new(VdfExample::<Sha3_256>::new(num_steps, options))),
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct VdfExample<H: ElementHasher> {
    options: ProofOptions,
    num_steps: usize,
    seed: BaseElement,
    result: BaseElement,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> VdfExample<H> {
    pub fn new(num_steps: usize, options: ProofOptions) -> Self {
        assert!(
            (num_steps + 1).is_power_of_two(),
            "number of steps must be one less than a power of 2"
        );

        // run the VDF function
        let now = Instant::now();
        let seed = BaseElement::new(123);
        let result = execute_vdf(seed, num_steps);
        println!(
            "Executed the VDF function for {} steps in {} ms",
            num_steps,
            now.elapsed().as_millis()
        );

        Self {
            options,
            num_steps,
            seed,
            result,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for VdfExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        println!("Generating proof for executing a VDF function for {} steps", self.num_steps);

        // create a prover
        let prover = VdfProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TRACE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = VdfProver::<H>::build_trace(self.seed, self.num_steps + 1);
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = VdfInputs { seed: self.seed, result: self.result };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<VdfAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let pub_inputs = VdfInputs {
            seed: self.seed,
            result: self.result + BaseElement::ONE,
        };
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<VdfAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            pub_inputs,
            &acceptable_options,
        )
    }
}

// VDF FUNCTION
// ================================================================================================

fn execute_vdf(seed: BaseElement, n: usize) -> BaseElement {
    let mut state = seed;
    for _ in 0..(n - 1) {
        state = (state - FORTY_TWO).exp(INV_ALPHA);
    }
    state
}
