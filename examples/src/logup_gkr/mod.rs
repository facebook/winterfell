// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;

use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::fields::f64::BaseElement,
    Proof, ProofOptions, Prover, VerifierError,
};

use crate::{Example, ExampleOptions, HashFunction};

mod air;
use air::LogUpGkrSimpleAir;

mod prover;
use prover::LogUpGkrSimpleProver;

#[cfg(test)]
mod tests;

// CONSTANTS AND TYPES
// ================================================================================================

const AUX_TRACE_WIDTH: usize = 2;

type Blake3_192 = winterfell::crypto::hashers::Blake3_192<BaseElement>;
type Blake3_256 = winterfell::crypto::hashers::Blake3_256<BaseElement>;
type Sha3_256 = winterfell::crypto::hashers::Sha3_256<BaseElement>;
type Rp64_256 = winterfell::crypto::hashers::Rp64_256;
type RpJive64_256 = winterfell::crypto::hashers::RpJive64_256;

// FIBONACCI EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    trace_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(28, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(LogUpGkrSimple::<Blake3_192>::new(trace_length, AUX_TRACE_WIDTH, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(LogUpGkrSimple::<Blake3_256>::new(trace_length, AUX_TRACE_WIDTH, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(LogUpGkrSimple::<Sha3_256>::new(trace_length, AUX_TRACE_WIDTH, options)))
        },
        HashFunction::Rp64_256 => {
            Ok(Box::new(LogUpGkrSimple::<Rp64_256>::new(trace_length, AUX_TRACE_WIDTH, options)))
        },
        HashFunction::RpJive64_256 => Ok(Box::new(LogUpGkrSimple::<RpJive64_256>::new(
            trace_length,
            AUX_TRACE_WIDTH,
            options,
        ))),
    }
}

#[derive(Clone, Debug)]
struct LogUpGkrSimple<H: ElementHasher<BaseField = BaseElement>> {
    trace_len: usize,
    aux_segment_width: usize,
    options: ProofOptions,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher<BaseField = BaseElement>> LogUpGkrSimple<H> {
    fn new(trace_len: usize, aux_segment_width: usize, options: ProofOptions) -> Self {
        assert!(trace_len < u32::MAX.try_into().unwrap());

        Self {
            trace_len,
            aux_segment_width,
            options,
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H> Example for LogUpGkrSimple<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync + Send,
{
    fn prove(&self) -> Proof {
        // create a prover
        let prover = LogUpGkrSimpleProver::<H>::new(AUX_TRACE_WIDTH, self.options.clone());

        let trace = prover.build_trace(self.trace_len, self.aux_segment_width);

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<LogUpGkrSimpleAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            (),
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        winterfell::verify::<LogUpGkrSimpleAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            (),
            &acceptable_options,
        )
    }
}
