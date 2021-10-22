// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains Winterfell STARK prover.
//!
//! This prover can be used to generate proofs of computational integrity using the
//! [STARK](https://eprint.iacr.org/2018/046) (Scalable Transparent ARguments of Knowledge)
//! protocol.
//!
//! When the crate is compiled with `concurrent` feature enabled, proof generation will be
//! performed in multiple threads (usually, as many threads as there are logical cores on the
//! machine). The number of threads can be configured via `RAYON_NUM_THREADS` environment
//! variable.
//!
//! # Usage
//! To generate a proof that a computation was executed correctly, you'll need to do the
//! following:
//!
//! 1. Define an *algebraic intermediate representation* (AIR) for your computation. This can
//!    be done by implementing [Air] trait.
//! 2. Execute your computation and record its execution trace in [ExecutionTrace] struct.
//! 3. Execute [prove()] function and supply the AIR of your computation together with its
//!    execution trace as input parameters. The function will produce a instance of [StarkProof]
//!    as an output.
//!
//! This `StarkProof` can be serialized and sent to a STARK verifier for verification. The size
//! of proof depends on the specifics of a given computation, but for most computations it should
//! be in the range between 15 KB (for very small computations) and 300 KB (for very large
//! computations).
//!
//! Proof generation time is also highly dependent on the specifics of a given computation, but
//! also depends on the capabilities of the machine used to generate the proofs (i.e. on number
//! of CPU cores and memory bandwidth).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

pub use air::{
    proof::StarkProof, Air, AirContext, Assertion, BoundaryConstraint, BoundaryConstraintGroup,
    ConstraintCompositionCoefficients, ConstraintDivisor, DeepCompositionCoefficients,
    EvaluationFrame, FieldExtension, HashFunction, ProofOptions, TraceInfo,
    TransitionConstraintDegree, TransitionConstraintGroup,
};
pub use utils::{
    iterators, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use fri::FriProver;
use utils::collections::Vec;

pub use math;
use math::{
    fft::infer_degree,
    fields::{CubeExtension, QuadExtension},
    FieldElement,
};

pub use crypto;
use crypto::{
    hashers::{Blake3_192, Blake3_256, Sha3_256},
    ElementHasher,
};

#[cfg(feature = "std")]
use log::debug;
#[cfg(feature = "std")]
use math::log2;
#[cfg(feature = "std")]
use std::time::Instant;

mod domain;
use domain::StarkDomain;

mod constraints;
use constraints::{ConstraintCommitment, ConstraintEvaluator};

mod composer;
use composer::DeepCompositionPoly;

mod trace;
use trace::TracePolyTable;
pub use trace::{ExecutionTrace, ExecutionTraceFragment};

mod channel;
use channel::ProverChannel;

mod errors;
pub use errors::ProverError;

#[cfg(test)]
pub mod tests;

// PROVER
// ================================================================================================
/// Returns a STARK proof attesting to a correct execution of a computation.
///
/// Function parameters have the following meanings:
/// * `AIR` is a type implementing [Air] trait for the computation. Among other things, it defines
///    algebraic constraints which define the computation.
/// * `trace` is an execution trace of the computation executed against some set of inputs. These
///   inputs may include both public and private inputs.
/// * `pub_inputs` is the set of public inputs against which the computation was executed. These
///   these inputs will need to be shared with the verifier in order for them to verify the proof.
/// * `options` defines basic protocol parameters such as: number of queries, blowup factor,
///   grinding factor, hash function to be used in the protocol etc. These properties directly
///   inform such metrics as proof generation time, proof size, and proof security level.
///
/// The function returns a [StarkProof] attesting that the specified `trace` is a valid execution
/// trace of the computation described by the specified `AIR` and generated using the specified
/// public inputs.
#[rustfmt::skip]
pub fn prove<AIR: Air>(
    trace: ExecutionTrace<AIR::BaseElement>,
    pub_inputs: AIR::PublicInputs,
    options: ProofOptions,
) -> Result<StarkProof, ProverError> {
    // serialize public inputs; these will be included in the seed for the public coin
    let mut pub_inputs_bytes = Vec::new();
    pub_inputs.write_into(&mut pub_inputs_bytes);

    // create an instance of AIR for the provided parameters. this takes a generic description of
    // the computation (provided via AIR type), and creates a description of a specific execution
    // of the computation for the provided public inputs.
    let air = AIR::new(trace.get_info(), pub_inputs, options);

    // make sure the specified trace is valid against the AIR. This checks validity of both,
    // assertions and state transitions. we do this in debug mode only because this is a very
    // expensive operation.
    #[cfg(debug_assertions)]
    trace.validate(&air);

    // figure out which version of the generic proof generation procedure to run. this is a sort
    // of static dispatch for selecting two generic parameter: extension field and hash function.
    match air.options().field_extension() {
        FieldExtension::None => match air.options().hash_fn() {
            HashFunction::Blake3_256 => generate_proof::
                <AIR, AIR::BaseElement, Blake3_256<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
            HashFunction::Blake3_192 => generate_proof::
                <AIR, AIR::BaseElement, Blake3_192<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
            HashFunction::Sha3_256 => generate_proof::
                <AIR, AIR::BaseElement, Sha3_256<AIR::BaseElement>>(air, trace, pub_inputs_bytes)
        },
        FieldExtension::Quadratic => match air.options().hash_fn() {
            HashFunction::Blake3_256 => generate_proof::
                <AIR, QuadExtension<AIR::BaseElement>, Blake3_256<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
            HashFunction::Blake3_192 => generate_proof::
                <AIR, QuadExtension<AIR::BaseElement>, Blake3_192<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
            HashFunction::Sha3_256 => generate_proof::
                <AIR, QuadExtension<AIR::BaseElement>, Sha3_256<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
        },
        FieldExtension::Cubic => match air.options().hash_fn() {
            HashFunction::Blake3_256 => generate_proof::
                <AIR, CubeExtension<AIR::BaseElement>, Blake3_256<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
            HashFunction::Blake3_192 => generate_proof::
                <AIR, CubeExtension<AIR::BaseElement>, Blake3_192<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
            HashFunction::Sha3_256 => generate_proof::
                <AIR, CubeExtension<AIR::BaseElement>, Sha3_256<AIR::BaseElement>>(air, trace, pub_inputs_bytes),
        },
    }
}

// PROOF GENERATION PROCEDURE
// ================================================================================================
/// Performs the actual proof generation procedure, generating the proof that the provided
/// execution `trace` is valid against the provided `air`.
fn generate_proof<A, E, H>(
    air: A,
    trace: ExecutionTrace<A::BaseElement>,
    pub_inputs_bytes: Vec<u8>,
) -> Result<StarkProof, ProverError>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseElement>,
    H: ElementHasher<BaseField = A::BaseElement>,
{
    // create a channel which is used to simulate interaction between the prover and the verifier;
    // the channel will be used to commit to values and to draw randomness that should come from
    // the verifier.
    let mut channel = ProverChannel::<A, E, H>::new(&air, pub_inputs_bytes);

    // 1 ----- extend execution trace -------------------------------------------------------------

    // build computation domain; this is used later for polynomial evaluations
    #[cfg(feature = "std")]
    let now = Instant::now();
    let domain = StarkDomain::new(&air);
    #[cfg(feature = "std")]
    debug!(
        "Built domain of 2^{} elements in {} ms",
        log2(domain.lde_domain_size()),
        now.elapsed().as_millis()
    );

    // extend the execution trace; this interpolates each register of the trace into a polynomial,
    // and then evaluates the polynomial over the LDE domain; each of the trace polynomials has
    // degree = trace_length - 1
    let (extended_trace, trace_polys) = trace.extend(&domain);
    #[cfg(feature = "std")]
    debug!(
        "Extended execution trace of {} registers from 2^{} to 2^{} steps ({}x blowup) in {} ms",
        extended_trace.width(),
        log2(trace_polys.poly_size()),
        log2(extended_trace.len()),
        extended_trace.blowup(),
        now.elapsed().as_millis()
    );

    // 2 ----- commit to the extended execution trace ---------------------------------------------
    #[cfg(feature = "std")]
    let now = Instant::now();
    let trace_tree = extended_trace.build_commitment::<H>();
    channel.commit_trace(*trace_tree.root());
    #[cfg(feature = "std")]
    debug!(
        "Committed to extended execution trace by building a Merkle tree of depth {} in {} ms",
        trace_tree.depth(),
        now.elapsed().as_millis()
    );

    // 3 ----- evaluate constraints ---------------------------------------------------------------
    // evaluate constraints specified by the AIR over the constraint evaluation domain, and compute
    // random linear combinations of these evaluations using coefficients drawn from the channel;
    // this step evaluates only constraint numerators, thus, only constraints with identical
    // denominators are merged together. the results are saved into a constraint evaluation table
    // where each column contains merged evaluations of constraints with identical denominators.
    #[cfg(feature = "std")]
    let now = Instant::now();
    let constraint_coeffs = channel.get_constraint_composition_coeffs();
    let evaluator = ConstraintEvaluator::new(&air, constraint_coeffs);
    let constraint_evaluations = evaluator.evaluate(&extended_trace, &domain);
    #[cfg(feature = "std")]
    debug!(
        "Evaluated constraints over domain of 2^{} elements in {} ms",
        log2(constraint_evaluations.num_rows()),
        now.elapsed().as_millis()
    );

    // 4 ----- commit to constraint evaluations ---------------------------------------------------

    // first, build constraint composition polynomial from the constraint evaluation table:
    // - divide all constraint evaluation columns by their respective divisors
    // - combine them into a single column of evaluations,
    // - interpolate the column into a polynomial in coefficient form
    // - "break" the polynomial into a set of column polynomials each of degree equal to
    //   trace_length - 1
    #[cfg(feature = "std")]
    let now = Instant::now();
    let composition_poly = constraint_evaluations.into_poly()?;
    #[cfg(feature = "std")]
    debug!(
        "Converted constraint evaluations into {} composition polynomial columns of degree {} in {} ms",
        composition_poly.num_columns(),
        composition_poly.column_degree(),
        now.elapsed().as_millis()
    );

    // then, evaluate composition polynomial columns over the LDE domain
    #[cfg(feature = "std")]
    let now = Instant::now();
    let composed_evaluations = composition_poly.evaluate(&domain);
    #[cfg(feature = "std")]
    debug!(
        "Evaluated composition polynomial columns over LDE domain (2^{} elements) in {} ms",
        log2(composed_evaluations[0].len()),
        now.elapsed().as_millis()
    );

    // finally, commit to the composition polynomial evaluations
    #[cfg(feature = "std")]
    let now = Instant::now();
    let constraint_commitment = ConstraintCommitment::<E, H>::new(composed_evaluations);
    channel.commit_constraints(constraint_commitment.root());
    #[cfg(feature = "std")]
    debug!(
        "Committed to composed evaluations by building a Merkle tree of depth {} in {} ms",
        constraint_commitment.tree_depth(),
        now.elapsed().as_millis()
    );

    // 5 ----- build DEEP composition polynomial --------------------------------------------------
    #[cfg(feature = "std")]
    let now = Instant::now();

    // draw an out-of-domain point z. Depending on the type of E, the point is drawn either
    // from the base field or from an extension field defined by E.
    //
    // The purpose of sampling from the extension field here (instead of the base field) is to
    // increase security. Soundness is limited by the size of the field that the random point
    // is drawn from, and we can potentially save on performance by only drawing this point
    // from an extension field, rather than increasing the size of the field overall.
    let z = channel.get_ood_point();

    // evaluate trace and constraint polynomials at the OOD point z, and send the results to
    // the verifier. the trace polynomials are actually evaluated over two points: z and z * g,
    // where g is the generator of the trace domain.
    let ood_frame = trace_polys.get_ood_frame(z);
    channel.send_ood_evaluation_frame(&ood_frame);

    let ood_evaluations = composition_poly.evaluate_at(z);
    channel.send_ood_constraint_evaluations(&ood_evaluations);

    // draw random coefficients to use during DEEP polynomial composition, and use them to
    // initialize the DEEP composition polynomial
    let deep_coefficients = channel.get_deep_composition_coeffs();
    let mut deep_composition_poly = DeepCompositionPoly::new(&air, z, deep_coefficients);

    // combine all trace polynomials together and merge them into the DEEP composition polynomial
    deep_composition_poly.add_trace_polys(trace_polys, ood_frame);

    // merge columns of constraint composition polynomial into the DEEP composition polynomial;
    deep_composition_poly.add_composition_poly(composition_poly, ood_evaluations);

    // raise the degree of the DEEP composition polynomial by one to make sure it is equal to
    // trace_length - 1
    deep_composition_poly.adjust_degree();

    #[cfg(feature = "std")]
    debug!(
        "Built DEEP composition polynomial of degree {} in {} ms",
        deep_composition_poly.degree(),
        now.elapsed().as_millis()
    );

    // make sure the degree of the DEEP composition polynomial is equal to trace polynomial degree
    assert_eq!(domain.trace_length() - 1, deep_composition_poly.degree());

    // 6 ----- evaluate DEEP composition polynomial over LDE domain -------------------------------
    #[cfg(feature = "std")]
    let now = Instant::now();
    let deep_evaluations = deep_composition_poly.evaluate(&domain);
    // we check the following condition in debug mode only because infer_degree is an expensive
    // operation
    debug_assert_eq!(
        domain.trace_length() - 1,
        infer_degree(&deep_evaluations, domain.offset())
    );
    #[cfg(feature = "std")]
    debug!(
        "Evaluated DEEP composition polynomial over LDE domain (2^{} elements) in {} ms",
        log2(domain.lde_domain_size()),
        now.elapsed().as_millis()
    );

    // 7 ----- compute FRI layers for the composition polynomial ----------------------------------
    #[cfg(feature = "std")]
    let now = Instant::now();
    let mut fri_prover = FriProver::new(air.options().to_fri_options());
    fri_prover.build_layers(&mut channel, deep_evaluations);
    #[cfg(feature = "std")]
    debug!(
        "Computed {} FRI layers from composition polynomial evaluations in {} ms",
        fri_prover.num_layers(),
        now.elapsed().as_millis()
    );

    // 8 ----- determine query positions ----------------------------------------------------------
    #[cfg(feature = "std")]
    let now = Instant::now();

    // apply proof-of-work to the query seed
    channel.grind_query_seed();

    // generate pseudo-random query positions
    let query_positions = channel.get_query_positions();
    #[cfg(feature = "std")]
    debug!(
        "Determined {} query positions in {} ms",
        query_positions.len(),
        now.elapsed().as_millis()
    );

    // 9 ----- build proof object -----------------------------------------------------------------
    #[cfg(feature = "std")]
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
    let proof = channel.build_proof(trace_queries, constraint_queries, fri_proof);
    #[cfg(feature = "std")]
    debug!("Built proof object in {} ms", now.elapsed().as_millis());

    Ok(proof)
}
