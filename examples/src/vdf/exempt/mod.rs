// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{Example, ExampleOptions};
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, log2, FieldElement},
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

pub fn get_example(options: ExampleOptions, num_steps: usize) -> Box<dyn Example> {
    Box::new(VdfExample::new(num_steps, options.to_proof_options(85, 2)))
}

pub struct VdfExample {
    options: ProofOptions,
    num_steps: usize,
    seed: BaseElement,
    result: BaseElement,
}

impl VdfExample {
    pub fn new(num_steps: usize, options: ProofOptions) -> Self {
        assert!(
            (num_steps + 1).is_power_of_two(),
            "number of steps must be one less than a power of 2"
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
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for VdfExample {
    fn prove(&self) -> StarkProof {
        debug!(
            "Generating proof for executing a VDF function for {} steps\n\
            ---------------------",
            self.num_steps
        );

        // create a prover
        let prover = VdfProver::new(self.options.clone());

        // generate execution trace
        let now = Instant::now();
        let trace = VdfProver::build_trace(self.seed, self.num_steps + 1);

        let trace_width = trace.width();
        let trace_length = trace.length();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace_width,
            log2(trace_length),
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
        winterfell::verify::<VdfAir>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = VdfInputs {
            seed: self.seed,
            result: self.result + BaseElement::ONE,
        };
        winterfell::verify::<VdfAir>(proof, pub_inputs)
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
