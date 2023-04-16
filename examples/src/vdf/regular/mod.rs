// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{Blake3_192, Blake3_256, Example, ExampleOptions, HashFunction, Sha3_256};
use core::marker::PhantomData;
use log::debug;
use std::time::Instant;
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher},
    math::{fields::f128::BaseElement, FieldElement},
    ProofOptions, Prover, StarkProof, Trace, TraceTable, VerifierError,
};

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
            num_steps.is_power_of_two(),
            "number of steps must be a power of 2"
        );

        // run the VDF function
        let now = Instant::now();
        let seed = BaseElement::new(123);
        let result = execute_vdf(seed, num_steps);
        debug!(
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
    H: ElementHasher<BaseField = BaseElement>,
{
    fn prove(&self) -> StarkProof {
        debug!(
            "Generating proof for executing a VDF function for {} steps\n\
            ---------------------",
            self.num_steps
        );

        // create a prover
        let prover = VdfProver::<H>::new(self.options.clone());

        // generate execution trace
        let now = Instant::now();
        let trace = VdfProver::<H>::build_trace(self.seed, self.num_steps);

        let trace_width = trace.width();
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace_width,
            trace_length.ilog2(),
            now.elapsed().as_millis()
        );

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = VdfInputs {
            seed: self.seed,
            result: self.result,
        };
        winterfell::verify::<VdfAir, H, DefaultRandomCoin<H>>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = VdfInputs {
            seed: self.seed,
            result: self.result + BaseElement::ONE,
        };
        winterfell::verify::<VdfAir, H, DefaultRandomCoin<H>>(proof, pub_inputs)
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
