// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::utils::compute_mulfib_term;
use crate::{Example, ExampleOptions};
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    ProofOptions, StarkProof, VerifierError,
};

mod air;
use air::{MulFib8Air, MulFib8TraceBuilder};

#[cfg(test)]
mod tests;

// FIBONACCI EXAMPLE
// ================================================================================================

pub fn get_example(options: ExampleOptions, sequence_length: usize) -> Box<dyn Example> {
    Box::new(MulFib8Example::new(
        sequence_length,
        options.to_proof_options(28, 8),
    ))
}

pub struct MulFib8Example {
    options: ProofOptions,
    sequence_length: usize,
    result: BaseElement,
}

impl MulFib8Example {
    pub fn new(sequence_length: usize, options: ProofOptions) -> MulFib8Example {
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

        MulFib8Example {
            options,
            sequence_length,
            result,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for MulFib8Example {
    fn prove(&self) -> StarkProof {
        debug!(
            "Generating proof for computing multiplicative Fibonacci sequence (8 terms per step) up to {}th term\n\
            ---------------------",
            self.sequence_length
        );

        // instantiate trace builder
        let trace_builder = MulFib8TraceBuilder::new(self.sequence_length);

        // generate the proof
        winterfell::prove::<MulFib8Air, MulFib8TraceBuilder>(
            trace_builder,
            self.result,
            self.options.clone(),
        )
        .unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        winterfell::verify::<MulFib8Air>(proof, self.result)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        winterfell::verify::<MulFib8Air>(proof, self.result + BaseElement::ONE)
    }
}
