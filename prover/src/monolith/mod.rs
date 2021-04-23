// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::channel::ProverChannel;
use common::{
    errors::ProverError, proof::StarkProof, Air, FieldExtension, HashFunction, ProofOptions,
    TraceInfo,
};
use crypto::hash::{Blake3_256, Sha3_256};
use math::field::QuadExtension;

mod domain;
use domain::StarkDomain;

mod constraints;
mod deep_fri;

mod trace;
pub use trace::{ExecutionTrace, ExecutionTraceFragment, TracePolyTable};

mod generation;
use generation::generate_proof;

// PROVER
// ================================================================================================

/// Generates a STARK proof attesting that the specified `trace` is a valid execution trace of the
/// computation described by AIR generated using the specified public inputs.
#[rustfmt::skip]
pub fn prove<AIR: Air>(
    trace: ExecutionTrace<AIR::BaseElement>,
    pub_inputs: AIR::PublicInputs,
    options: ProofOptions,
) -> Result<StarkProof, ProverError> {
    // create an instance of AIR for the provided parameters. this takes a generic description of
    // the computation (provided via AIR type), and creates a description of a specific execution
    // of the computation for the provided public inputs.
    let trace_info = TraceInfo {
        length: trace.len(),
        meta: Vec::new(),
    };
    let air = AIR::new(trace_info, pub_inputs, options);

    // make sure the specified trace is valid against the AIR. This checks validity of both,
    // assertions and state transitions. we do this in debug mode only because this is a very
    // expensive operation.
    #[cfg(debug_assertions)]
    trace.validate(&air);

    // figure out which version of the generic proof generation procedure to run. this is a sort
    // of static dispatch for selecting two generic parameter: extension field and hash function.
    match air.context().options().field_extension() {
        FieldExtension::None => match air.context().options().hash_fn() {
            HashFunction::Blake3_256 => {
                generate_proof::<AIR, AIR::BaseElement, Blake3_256>(air, trace)
            }
            HashFunction::Sha3_256 => {
                generate_proof::<AIR, AIR::BaseElement, Sha3_256>(air, trace)
            },
        },
        FieldExtension::Quadratic => match air.context().options().hash_fn() {
            HashFunction::Blake3_256 => {
                generate_proof::<AIR, QuadExtension<AIR::BaseElement>, Blake3_256>(air, trace)
            }
            HashFunction::Sha3_256 => {
                generate_proof::<AIR, QuadExtension<AIR::BaseElement>, Sha3_256>(air, trace)
            }
        },
    }
}
