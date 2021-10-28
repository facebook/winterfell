// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::utils::compute_fib_term;
use crate::{Example, ExampleOptions};
use log::debug;
use std::time::Instant;
use winterfell::{
    math::{fields::f128::BaseElement, FieldElement},
    ProofOptions, StarkProof, VerifierError,
};

mod air;
use air::{Fib8Air, Fib8TraceBuilder};

#[cfg(test)]
mod tests;

// FIBONACCI EXAMPLE
// ================================================================================================

pub fn get_example(options: ExampleOptions, sequence_length: usize) -> Box<dyn Example> {
    Box::new(Fib8Example::new(
        sequence_length,
        options.to_proof_options(28, 8),
    ))
}

pub struct Fib8Example {
    options: ProofOptions,
    sequence_length: usize,
    result: BaseElement,
}

impl Fib8Example {
    pub fn new(sequence_length: usize, options: ProofOptions) -> Fib8Example {
        assert!(
            sequence_length.is_power_of_two(),
            "sequence length must be a power of 2"
        );

        // compute Fibonacci sequence
        let now = Instant::now();
        let result = compute_fib_term(sequence_length);
        debug!(
            "Computed Fibonacci sequence up to {}th term in {} ms",
            sequence_length,
            now.elapsed().as_millis()
        );

        Fib8Example {
            options,
            sequence_length,
            result,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for Fib8Example {
    fn prove(&self) -> StarkProof {
        debug!(
            "Generating proof for computing Fibonacci sequence (8 terms per step) up to {}th term\n\
            ---------------------",
            self.sequence_length
        );

        // instantiate trace builder
        let trace_builder = Fib8TraceBuilder::new(self.sequence_length);

        // generate the proof
        winterfell::prove::<Fib8Air, Fib8TraceBuilder>(
            trace_builder,
            self.result,
            self.options.clone(),
        )
        .unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        winterfell::verify::<Fib8Air>(proof, self.result)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        winterfell::verify::<Fib8Air>(proof, self.result + BaseElement::ONE)
    }
}
