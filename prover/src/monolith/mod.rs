// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::channel::ProverChannel;
use common::{
    errors::ProverError, proof::StarkProof, Air, FieldExtension, HashFunction, ProofOptions,
    PublicCoin, TraceInfo,
};
use crypto::hash::{Blake3_256, Hasher, Sha3_256};
use log::debug;
use math::{
    fft::infer_degree,
    field::{FieldElement, QuadExtension},
    utils::log2,
};
use std::time::Instant;

mod domain;
use domain::StarkDomain;

mod constraints;
use constraints::{ConstraintCommitment, ConstraintEvaluator};

mod composer;
use composer::DeepCompositionPoly;

mod trace;
pub use trace::{ExecutionTrace, ExecutionTraceFragment, TracePolyTable};

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

// PROOF GENERATION PROCEDURE
// ================================================================================================
/// Performs the actual proof generation procedure, generating the proof that the provided
/// execution `trace` is valid against the provided `air`.
fn generate_proof<A: Air, E: FieldElement + From<A::BaseElement>, H: Hasher>(
    air: A,
    trace: ExecutionTrace<A::BaseElement>,
) -> Result<StarkProof, ProverError> {
    // create a channel; this simulates interaction between the prover and the verifier;
    // the channel will be used to commit to values and to draw randomness that should
    // come from the verifier
    let mut channel = ProverChannel::<H>::new(air.context());

    // 1 ----- extend execution trace -------------------------------------------------------------

    // build computation domain; this is used later for polynomial evaluations
    let now = Instant::now();
    let domain = StarkDomain::new(air.context());
    debug!(
        "Built domain of 2^{} elements in {} ms",
        log2(domain.lde_domain_size()),
        now.elapsed().as_millis()
    );

    // extend the execution trace; this interpolates each register of the trace into a polynomial,
    // and then evaluates the polynomial over the LDE domain; each of the trace polynomials has
    // degree = trace_length - 1
    let (extended_trace, trace_polys) = trace.extend(&domain);
    debug!(
        "Extended execution trace of {} registers from 2^{} to 2^{} steps ({}x blowup) in {} ms",
        extended_trace.width(),
        log2(trace_polys.poly_size()),
        log2(extended_trace.len()),
        extended_trace.blowup(),
        now.elapsed().as_millis()
    );

    // 2 ----- commit to the extended execution trace ---------------------------------------------
    let now = Instant::now();
    let trace_tree = extended_trace.build_commitment::<H>();
    channel.commit_trace(*trace_tree.root());
    debug!(
        "Committed to extended execution trace by building a Merkle tree of depth {} in {} ms",
        trace_tree.depth(),
        now.elapsed().as_millis()
    );

    // 3 ----- evaluate constraints ---------------------------------------------------------------
    let now = Instant::now();

    // build constraint evaluator; first, get a PRNG from the channel to build a set of
    // coefficients for random linear combinations of constraint evaluations
    let mut constraint_coeff_prng = channel.get_constraint_composition_prng();
    let constraint_coeffs = air.get_constraint_composition_coeffs(&mut constraint_coeff_prng);
    let evaluator = ConstraintEvaluator::new(&air, constraint_coeffs);

    // apply constraint evaluator to the extended trace table to generate a constraint evaluation
    // table
    let constraint_evaluations = evaluator.evaluate(&extended_trace, &domain);
    debug!(
        "Evaluated constraints over domain of 2^{} elements in {} ms",
        log2(constraint_evaluations.num_rows()),
        now.elapsed().as_millis()
    );

    // 4 ----- commit to constraint evaluations ---------------------------------------------------

    // first, build constraint composition polynomial from all constraint evaluations
    let now = Instant::now();
    let composition_poly = constraint_evaluations.into_poly()?;
    debug!(
        "Converted constraint evaluations into {} composition polynomial columns of degree {} in {} ms",
        composition_poly.num_columns(),
        composition_poly.column_degree(),
        now.elapsed().as_millis()
    );

    // then, evaluate composition polynomial columns over the LDE domain
    let now = Instant::now();
    let composed_evaluations = composition_poly.evaluate(&domain);
    debug!(
        "Evaluated composition polynomial columns over LDE domain (2^{} elements) in {} ms",
        log2(composed_evaluations[0].len()),
        now.elapsed().as_millis()
    );

    // finally, commit to the composition polynomial evaluations
    let now = Instant::now();
    let constraint_commitment = ConstraintCommitment::<E, H>::new(composed_evaluations);
    channel.commit_constraints(constraint_commitment.root());
    debug!(
        "Committed to composed evaluations by building a Merkle tree of depth {} in {} ms",
        constraint_commitment.tree_depth(),
        now.elapsed().as_millis()
    );

    // 5 ----- build DEEP composition polynomial --------------------------------------------------
    let now = Instant::now();

    // draw an out-of-domain point z. Depending on the type of E, the point is drawn either
    // from the base field or from an extension field defined by E.
    //
    // The purpose of sampling from the extension field here (instead of the base field) is to
    // increase security. Soundness is limited by the size of the field that the random point
    // is drawn from, and we can potentially save on performance by only drawing this point
    // from an extension field, rather than increasing the size of the field overall.
    let mut deep_prng = channel.get_deep_composition_prng();

    let z = deep_prng.draw::<E>();

    // draw random coefficients to use during polynomial composition
    let deep_coefficients = air.get_deep_composition_coeffs::<H, E>(&mut deep_prng);

    // initialize composition polynomial
    let mut deep_composition_poly = DeepCompositionPoly::new(&air, z, deep_coefficients);

    // combine all trace polynomials together and merge them into the DEEP composition polynomial;
    // ood_frame are trace states at two out-of-domain points, and will go into the proof
    let ood_frame = deep_composition_poly.add_trace_polys(trace_polys);

    // merge columns of constraint composition polynomial into the DEEP composition polynomial;
    // ood_evaluations are the evaluations of composition polynomial columns at out-of-domain
    // point, and will go into the proof
    let ood_evaluations = deep_composition_poly.add_composition_poly(composition_poly);

    // raise the degree of the DEEP composition polynomial by one to make sure it is equal to
    // trace_length - 1
    deep_composition_poly.adjust_degree();

    debug!(
        "Built DEEP composition polynomial of degree {} in {} ms",
        deep_composition_poly.degree(),
        now.elapsed().as_millis()
    );

    // make sure the degree of the DEEP composition polynomial is equal to trace polynomial degree
    assert_eq!(domain.trace_length() - 1, deep_composition_poly.degree());

    // 6 ----- evaluate DEEP composition polynomial over LDE domain -------------------------------
    let now = Instant::now();
    let deep_evaluations = deep_composition_poly.evaluate(&domain);
    // we check the following condition in debug mode only because infer_degree is an expensive
    // operation
    debug_assert_eq!(
        domain.trace_length() - 1,
        infer_degree(&deep_evaluations, domain.offset())
    );
    debug!(
        "Evaluated DEEP composition polynomial over LDE domain (2^{} elements) in {} ms",
        log2(domain.lde_domain_size()),
        now.elapsed().as_millis()
    );

    // 7 ----- compute FRI layers for the composition polynomial ----------------------------------
    let now = Instant::now();
    let mut fri_prover = fri::FriProver::new(air.options().to_fri_options());
    fri_prover.build_layers(&mut channel, deep_evaluations, &domain.lde_values());
    debug!(
        "Computed {} FRI layers from composition polynomial evaluations in {} ms",
        fri_prover.num_layers(),
        now.elapsed().as_millis()
    );

    // 8 ----- determine query positions ----------------------------------------------------------
    let now = Instant::now();

    // apply proof-of-work to the query seed
    channel.grind_query_seed();

    // generate pseudo-random query positions
    let query_positions = channel.draw_query_positions();
    debug!(
        "Determined {} query positions in {} ms",
        query_positions.len(),
        now.elapsed().as_millis()
    );

    // 9 ----- build proof object -----------------------------------------------------------------
    let now = Instant::now();

    // generate FRI proof
    let fri_proof = fri_prover.build_proof(&query_positions);

    // query the execution trace at the selected position; for each query, we need the
    // state of the trace at that position + Merkle authentication path
    let trace_queries = extended_trace.query(trace_tree, &query_positions);

    // query the constraint commitment at the selected positions; for each query, we need just
    // a Merkle authentication path. this is because constraint evaluations for each step are
    // merged into a single value and Merkle authentication paths contain these values already
    let constraint_queries = constraint_commitment.query(&query_positions);

    // build the proof object
    let proof = channel.build_proof::<A::BaseElement, E>(
        trace_queries,
        constraint_queries,
        ood_frame,
        ood_evaluations,
        fri_proof,
    );
    debug!("Built proof object in {} ms", now.elapsed().as_millis());

    Ok(proof)
}
