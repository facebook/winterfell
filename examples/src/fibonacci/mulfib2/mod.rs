// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::utils::compute_mulfib_term;
use crate::{Example, ExampleOptions};
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, log2, FieldElement},
    ProofOptions, Prover, StarkProof, Trace, TraceTable, VerifierError,
};

mod air;
use air::MulFib2Air;

mod prover;
use prover::MulFib2Prover;

#[cfg(test)]
mod tests;

// FIBONACCI EXAMPLE
// ================================================================================================

pub fn get_example(options: ExampleOptions, sequence_length: usize) -> Box<dyn Example> {
    Box::new(MulFib2Example::new(
        sequence_length,
        options.to_proof_options(28, 8),
    ))
}
pub struct MulFib2Example {
    options: ProofOptions,
    sequence_length: usize,
    result: BaseElement,
}

impl MulFib2Example {
    pub fn new(sequence_length: usize, options: ProofOptions) -> MulFib2Example {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        // compute Fibonacci sequence
        let now = Instant::now();
        let result = compute_mulfib_term(sequence_length);
        debug!(
            "Computed multiplicative Fibonacci sequence up to {}th term in {} ms",
            sequence_length,
            now.elapsed().as_millis()
        );

        MulFib2Example {
            options,
            sequence_length,
            result,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for MulFib2Example {
    fn prove(&self) -> StarkProof {
        let sequence_length = self.sequence_length;
        debug!(
            "Generating proof for computing multiplicative Fibonacci sequence (2 terms per step) up to {}th term\n\
            ---------------------",
            sequence_length
        );

        // create a prover
        let prover = MulFib2Prover::new(self.options.clone());

        // generate execution trace
        let now = Instant::now();
        let trace = prover.build_trace(sequence_length);
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
        winterfell::verify::<MulFib2Air>(proof, self.result)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        winterfell::verify::<MulFib2Air>(proof, self.result + BaseElement::ONE)
    }
}
