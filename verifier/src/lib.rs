// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::PublicCoin;
pub use common::{
    errors::VerifierError, proof::StarkProof, Air, FieldExtension, HashFunction, TraceInfo,
};
use fri::VerifierChannel as FriVerifierChannel;

pub use crypto;
use crypto::hash::{Blake3_256, Hasher, Sha3_256};

pub use math;
use math::field::{FieldElement, QuadExtension};

mod channel;
use channel::VerifierChannel;

mod evaluator;
use evaluator::evaluate_constraints;

mod composer;
use composer::DeepComposer;

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

// VERIFICATION PROCEDURE
// ================================================================================================

/// Performs the actual verification by reading the data from the `channel` and making sure it
/// attests to a correct execution of the computation specified by the provided `air`.
fn perform_verification<A: Air, E: FieldElement + From<A::BaseElement>, H: Hasher>(
    air: A,
    channel: VerifierChannel<A::BaseElement, E, H>,
) -> Result<(), VerifierError> {
    // 1 ----- Check consistency of constraint evaluations at OOD point z -------------------------
    // make sure that evaluations obtained by evaluating constraints over out-of-domain frame are
    // consistent with evaluations of composition polynomial columns sent by the prover

    // first, draw a pseudo-random out-of-domain point
    let z = channel.draw_deep_point::<E>();

    // then, evaluate constraints over the out-of-domain evaluation frame
    let ood_frame = channel.read_ood_evaluation_frame();
    let ood_constraint_evaluation_1 = evaluate_constraints(&air, &channel, ood_frame, z);

    // then, read evaluations of composition polynomial columns and reduce them to a single
    // value by computing sum(z^i * value_i), where value_i is the evaluation of the ith column
    // polynomial at z^m, where m is the total number of column polynomials.
    let ood_evaluations = channel.read_ood_evaluations();
    let ood_constraint_evaluation_2 = ood_evaluations
        .iter()
        .enumerate()
        .fold(E::ZERO, |result, (i, &value)| {
            result + z.exp((i as u32).into()) * value
        });

    // finally, make sure the values are the same
    if ood_constraint_evaluation_1 != ood_constraint_evaluation_2 {
        return Err(VerifierError::InconsistentOodConstraintEvaluations);
    }

    // 2 ----- Read queried trace states and constraint evaluations -------------------------------

    // draw pseudo-random query positions in LDE domain
    let query_positions = channel.draw_query_positions();

    // read trace states and constraint evaluations at the queried positions; this also checks
    // that Merkle authentication paths for the states and evaluations are valid
    let queried_trace_states = channel.read_trace_states(&query_positions)?;
    let queried_evaluations = channel.read_constraint_evaluations(&query_positions)?;

    // 3 ----- Compute composition polynomial evaluations -----------------------------------------

    // draw coefficients for computing random linear combination of trace and constraint
    // polynomials, and use them to instantiate a composer for DEEP composition polynomial
    let coefficients = channel.draw_composition_coefficients();
    let composer = DeepComposer::new(&air, &query_positions, z, coefficients);

    // compute evaluations of DEEP composition polynomial by combining compositions of trace
    // registers and constraint evaluations, and raising their degree by one
    let t_composition = composer.compose_registers(queried_trace_states, ood_frame);
    let c_composition = composer.compose_constraints(queried_evaluations, ood_evaluations);
    let deep_evaluations = composer.combine_compositions(t_composition, c_composition);

    // 4 ----- Verify low-degree proof -------------------------------------------------------------
    // make sure that evaluations we computed in the previous step are in fact evaluations of a
    // polynomial of degree equal to trace polynomial degree
    let fri_context = fri::VerifierContext::new(
        air.lde_domain_size(),
        air.trace_poly_degree(),
        channel.num_fri_partitions(),
        air.options().to_fri_options::<A::BaseElement>(),
    );
    fri::verify(&fri_context, &channel, &deep_evaluations, &query_positions)
        .map_err(VerifierError::FriVerificationFailed)
}
