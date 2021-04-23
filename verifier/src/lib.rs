// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

pub use common::{
    errors::VerifierError, proof::StarkProof, Air, FieldExtension, HashFunction, TraceInfo,
};

pub use crypto;
use crypto::hash::{Blake3_256, Sha3_256};

pub use math;
use math::field::QuadExtension;

mod channel;
use channel::VerifierChannel;

mod verification;
use verification::perform_verification;

mod constraints;
use constraints::{compose_constraints, evaluate_constraints};

// VERIFIER
// ================================================================================================

/// Verifies STARK `proof` attesting that the computation specified by `AIR` was executed correctly
/// against the provided `pub_inputs`.
#[rustfmt::skip]
pub fn verify<AIR: Air>(
    proof: StarkProof,
    pub_inputs: AIR::PublicInputs,
) -> Result<(), VerifierError> {
    // ----- create AIR instance for the computation specified in the proof -----------------------
    let trace_info = TraceInfo {
        length: proof.trace_length(),
        meta: vec![],
    };
    let air = AIR::new(trace_info, pub_inputs, proof.options().clone());

    // ----- instantiate verifier channel and run the verification --------------------------------
    // figure out which version of the generic proof verification procedure to run. this is a sort
    // of static dispatch for selecting two generic parameter: extension field and hash function.
    match air.context().options().field_extension() {
        FieldExtension::None => match air.context().options().hash_fn() {
            HashFunction::Blake3_256 => {
                let channel = VerifierChannel::new(&air, proof)?;
                perform_verification::<AIR, AIR::BaseElement, Blake3_256>(air, channel)
            }
            HashFunction::Sha3_256 => {
                let channel = VerifierChannel::new(&air, proof)?;
                perform_verification::<AIR, AIR::BaseElement, Sha3_256>(air, channel)
            }
        },
        FieldExtension::Quadratic => match air.context().options().hash_fn() {
            HashFunction::Blake3_256 => {
                let channel = VerifierChannel::new(&air, proof)?;
                perform_verification::<AIR, QuadExtension<AIR::BaseElement>, Blake3_256>(air, channel)
            }
            HashFunction::Sha3_256 => {
                let channel = VerifierChannel::new(&air, proof)?;
                perform_verification::<AIR, QuadExtension<AIR::BaseElement>, Sha3_256>(air, channel)
            }
        },
    }
}
