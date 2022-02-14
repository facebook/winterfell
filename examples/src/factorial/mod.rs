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
use air::FactAir;

mod prover;
use prover::FactProver;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const TRACE_WIDTH: usize = 2;

// Factorial EXAMPLE
// ================================================================================================

pub fn get_example(options: ExampleOptions, sequence_length: usize) -> Box<dyn Example> {
    Box::new(FactExample::new(
        sequence_length,
        options.to_proof_options(28, 8),
    ))
}

pub struct FactExample {
    options: ProofOptions,
    sequence_length: usize,
    result: BaseElement,
}

impl FactExample {
    pub fn new(sequence_length: usize, options: ProofOptions) -> FactExample {
        // compute Fibonacci sequence
        let now = Instant::now();
        let result = compute_fact_term(sequence_length);
        debug!(
            "Computed factorial sequence up to {}th term in {} ms",
            sequence_length,
            now.elapsed().as_millis()
        );

        FactExample {
            options,
            sequence_length,
            result,
        }
    }
}

pub fn compute_fact_term(n: usize) -> BaseElement {
    let mut t1 = BaseElement::ONE;

    for i in 0..(n - 1) {
        t1 = t1 * BaseElement::new(i.try_into().unwrap());
    }

    t1
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for FactExample {
    fn prove(&self) -> StarkProof {
        debug!(
            "Generating proof for computing Fibonacci sequence (1 terms per step) up to {}th term\n\
            ---------------------",
            self.sequence_length
        );

        // create a prover
        let prover = FactProver::new(self.options.clone());

        // generate execution trace
        let now = Instant::now();
        let trace = prover.build_trace(self.sequence_length);

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
        winterfell::verify::<FactAir>(proof, self.result)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        winterfell::verify::<FactAir>(proof, self.result + BaseElement::ONE)
    }
}