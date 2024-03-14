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
//! 2. Define an execution trace for your computation. This can be done by implementing [Trace]
//!    trait. Alternatively, you can use [TraceTable] struct which already implements [Trace]
//!    trait in cases when this generic implementation works for your use case.
//! 3. Execute your computation and record its execution trace.
//! 4. Define your prover by implementing [Prover] trait. Then execute [Prover::prove()] function
//!    passing the trace generated in the previous step into it as a parameter. The function will
//!    return a instance of [StarkProof].
//!
//! This [StarkProof] can be serialized and sent to a STARK verifier for verification. The size
//! of proof depends on the specifics of a given computation, but for most computations it should
//! be in the range between 15 KB (for very small computations) and 300 KB (for very large
//! computations).
//!
//! Proof generation time is also highly dependent on the specifics of a given computation, but
//! also depends on the capabilities of the machine used to generate the proofs (i.e. on number
//! of CPU cores and memory bandwidth).

#![no_std]

#[macro_use]
extern crate alloc;

pub use air::{
    proof, proof::StarkProof, Air, AirContext, Assertion, AuxTraceRandElements, BoundaryConstraint,
    BoundaryConstraintGroup, ConstraintCompositionCoefficients, ConstraintDivisor,
    DeepCompositionCoefficients, EvaluationFrame, FieldExtension, ProofOptions, TraceInfo,
    TraceLayout, TransitionConstraintDegree,
};
use tracing::{event, info_span, Level};
pub use utils::{
    iterators, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    SliceReader,
};

use alloc::vec::Vec;
use fri::FriProver;

pub use math;
use math::{
    fft::infer_degree,
    fields::{CubeExtension, QuadExtension},
    ExtensibleField, FieldElement, StarkField, ToElements,
};

pub use crypto;
use crypto::{ElementHasher, RandomCoin};

mod domain;
pub use domain::StarkDomain;

pub mod matrix;
use matrix::{ColMatrix, RowMatrix};

mod constraints;
pub use constraints::{
    CompositionPoly, CompositionPolyTrace, ConstraintCommitment, ConstraintEvaluator,
    DefaultConstraintEvaluator,
};

mod composer;
use composer::DeepCompositionPoly;

mod trace;
pub use trace::{DefaultTraceLde, Trace, TraceLde, TracePolyTable, TraceTable, TraceTableFragment};

mod channel;
use channel::ProverChannel;

mod errors;
pub use errors::ProverError;

#[cfg(test)]
pub mod tests;

// PROVER
// ================================================================================================

// this segment width seems to give the best performance for small fields (i.e., 64 bits)
const DEFAULT_SEGMENT_WIDTH: usize = 8;

/// Defines a STARK prover for a computation.
///
/// A STARK prover can be used to generate STARK proofs. The prover contains definitions of a
/// computation's AIR (specified via [Air](Prover::Air) associated type), execution trace
/// (specified via [Trace](Prover::Trace) associated type) and hash function to be used (specified
/// via [HashFn](Prover::HashFn) associated type), and exposes [prove()](Prover::prove) method which
/// can be used to build STARK proofs for provided execution traces.
///
/// Thus, once a prover is defined and instantiated, generating a STARK proof consists of two
/// steps:
/// 1. Build an execution trace for a specific instance of the computation.
/// 2. Invoke [Prover::prove()] method generate a proof using the trace from the previous step
///    as a witness.
///
/// The generated proof is built using protocol parameters defined by the [ProofOptions] struct
/// return from [Prover::options] method.
///
/// To further customize the prover, implementers can specify custom implementations of the
/// [RandomCoin], [TraceLde], and [ConstraintEvaluator] associated types (default implementations
/// of these types are provided with the prover). For example, providing custom implementations
/// of [TraceLde] and/or [ConstraintEvaluator] can be beneficial when some steps of proof
/// generation can be delegated to non-CPU hardware (e.g., GPUs).
pub trait Prover {
    /// Base field for the computation described by this prover.
    type BaseField: StarkField + ExtensibleField<2> + ExtensibleField<3>;

    /// Algebraic intermediate representation (AIR) for the computation described by this prover.
    type Air: Air<BaseField = Self::BaseField>;

    /// Execution trace of the computation described by this prover.
    type Trace: Trace<BaseField = Self::BaseField>;

    /// Hash function to be used.
    type HashFn: ElementHasher<BaseField = Self::BaseField>;

    /// PRNG to be used for generating random field elements.
    type RandomCoin: RandomCoin<BaseField = Self::BaseField, Hasher = Self::HashFn>;

    /// Trace low-degree extension for building the LDEs of trace segments and their commitments.
    type TraceLde<E>: TraceLde<E, HashFn = Self::HashFn>
    where
        E: FieldElement<BaseField = Self::BaseField>;

    /// Constraints evaluator used to evaluate AIR constraints over the extended execution trace.
    type ConstraintEvaluator<'a, E>: ConstraintEvaluator<E, Air = Self::Air>
    where
        E: FieldElement<BaseField = Self::BaseField>;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a set of public inputs for an instance of the computation defined by the provided
    /// trace.
    ///
    /// Public inputs need to be shared with the verifier in order for them to verify a proof.
    fn get_pub_inputs(&self, trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs;

    /// Returns [ProofOptions] which this prover uses to generate STARK proofs.
    ///
    /// Proof options defines basic protocol parameters such as: number of queries, blowup factor,
    /// grinding factor etc. These properties directly inform such metrics as proof generation time,
    /// proof size, and proof security level.
    fn options(&self) -> &ProofOptions;

    /// Takes the main trace segment columns as input, interpolates them into polynomials in
    /// coefficient form, and evaluates the polynomials over the LDE domain.
    ///
    /// Returns a tuple containing a [TracePolyTable] with the trace polynomials for the main trace
    /// and a new [TraceLde] instance from which the LDE and trace commitments can be obtained.
    fn new_trace_lde<E>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>)
    where
        E: FieldElement<BaseField = Self::BaseField>;

    /// Returns a new constraint evaluator which can be used to evaluate transition and boundary
    /// constraints over the extended execution trace.
    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: AuxTraceRandElements<E>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: FieldElement<BaseField = Self::BaseField>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a STARK proof attesting to a correct execution of a computation defined by the
    /// provided trace.
    ///
    /// The returned [StarkProof] attests that the specified `trace` is a valid execution trace of
    /// the computation described by [Self::Air](Prover::Air) and generated using some set of
    /// secret and public inputs. Public inputs must match the value returned from
    /// [Self::get_pub_inputs()](Prover::get_pub_inputs) for the provided trace.
    fn prove(&self, trace: Self::Trace) -> Result<StarkProof, ProverError> {
        // figure out which version of the generic proof generation procedure to run. this is a sort
        // of static dispatch for selecting two generic parameter: extension field and hash
        // function.
        match self.options().field_extension() {
            FieldExtension::None => self.generate_proof::<Self::BaseField>(trace),
            FieldExtension::Quadratic => {
                if !<QuadExtension<Self::BaseField>>::is_supported() {
                    return Err(ProverError::UnsupportedFieldExtension(2));
                }
                self.generate_proof::<QuadExtension<Self::BaseField>>(trace)
            }
            FieldExtension::Cubic => {
                if !<CubeExtension<Self::BaseField>>::is_supported() {
                    return Err(ProverError::UnsupportedFieldExtension(3));
                }
                self.generate_proof::<CubeExtension<Self::BaseField>>(trace)
            }
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Performs the actual proof generation procedure, generating the proof that the provided
    /// execution `trace` is valid against this prover's AIR.
    /// TODO: make this function un-callable externally?
    #[doc(hidden)]
    fn generate_proof<E>(&self, mut trace: Self::Trace) -> Result<StarkProof, ProverError>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        // 0 ----- instantiate AIR and prover channel ---------------------------------------------

        // serialize public inputs; these will be included in the seed for the public coin
        let pub_inputs = self.get_pub_inputs(&trace);
        let pub_inputs_elements = pub_inputs.to_elements();

        // create an instance of AIR for the provided parameters. this takes a generic description
        // of the computation (provided via AIR type), and creates a description of a specific
        // execution of the computation for the provided public inputs.
        let air = Self::Air::new(trace.get_info(), pub_inputs, self.options().clone());

        // create a channel which is used to simulate interaction between the prover and the
        // verifier; the channel will be used to commit to values and to draw randomness that
        // should come from the verifier.
        let mut channel = ProverChannel::<Self::Air, E, Self::HashFn, Self::RandomCoin>::new(
            &air,
            pub_inputs_elements,
        );

        // 1 ----- Commit to the execution trace --------------------------------------------------

        // build computation domain; this is used later for polynomial evaluations
        let lde_domain_size = air.lde_domain_size();
        let trace_length = air.trace_length();
        let domain = info_span!("build_domain", trace_length, lde_domain_size)
            .in_scope(|| StarkDomain::new(&air));
        assert_eq!(domain.lde_domain_size(), lde_domain_size);
        assert_eq!(domain.trace_length(), trace_length);

        // commit to the main trace segment
        let (mut trace_lde, mut trace_polys) = {
            // extend the main execution trace and build a Merkle tree from the extended trace
            let span = info_span!("commit_to_main_trace_segment").entered();
            let (trace_lde, trace_polys) =
                self.new_trace_lde(&trace.get_info(), trace.main_segment(), &domain);

            // get the commitment to the main trace segment LDE
            let main_trace_root = trace_lde.get_main_trace_commitment();

            // commit to the LDE of the main trace by writing the root of its Merkle tree into
            // the channel
            channel.commit_trace(main_trace_root);

            drop(span);
            (trace_lde, trace_polys)
        };

        // build auxiliary trace segments (if any), and append the resulting segments to trace
        // commitment and trace polynomial table structs
        let mut aux_trace_segments = Vec::new();
        let mut aux_trace_rand_elements = AuxTraceRandElements::new();
        for i in 0..trace.layout().num_aux_segments() {
            let num_columns = trace.layout().get_aux_segment_width(i);
            let (aux_segment, rand_elements) = {
                let span = info_span!("build_aux_trace_segment", num_columns).entered();

                // draw a set of random elements required to build an auxiliary trace segment
                let rand_elements = channel.get_aux_trace_segment_rand_elements(i);

                // build the trace segment
                let aux_segment = trace
                    .build_aux_segment(&aux_trace_segments, &rand_elements)
                    .expect("failed build auxiliary trace segment");

                drop(span);
                (aux_segment, rand_elements)
            };
            assert_eq!(aux_segment.num_cols(), num_columns);
            assert_eq!(aux_segment.num_rows(), trace_length);

            // commit to the auxiliary trace segment
            let aux_segment_polys = {
                // extend the auxiliary trace segment and build a Merkle tree from the extended
                // trace
                let span = info_span!("commit_to_aux_trace_segment").entered();
                let (aux_segment_polys, aux_segment_root) =
                    trace_lde.add_aux_segment(&aux_segment, &domain);

                // commit to the LDE of the extended auxiliary trace segment by writing the root of
                // its Merkle tree into the channel
                channel.commit_trace(aux_segment_root);

                drop(span);
                aux_segment_polys
            };

            trace_polys.add_aux_segment(aux_segment_polys);
            aux_trace_rand_elements.add_segment_elements(rand_elements);
            aux_trace_segments.push(aux_segment);
        }

        // make sure the specified trace (including auxiliary segments) is valid against the AIR.
        // This checks validity of both, assertions and state transitions. We do this in debug
        // mode only because this is a very expensive operation.
        #[cfg(debug_assertions)]
        trace.validate(&air, &aux_trace_segments, &aux_trace_rand_elements);

        // drop the main trace and aux trace segments as they are no longer needed
        drop(trace);
        drop(aux_trace_segments);

        // 2 ----- evaluate constraints -----------------------------------------------------------
        // evaluate constraints specified by the AIR over the constraint evaluation domain, and
        // compute random linear combinations of these evaluations using coefficients drawn from
        // the channel
        let ce_domain_size = air.ce_domain_size();
        let composition_poly_trace =
            info_span!("evaluate_constraints", ce_domain_size).in_scope(|| {
                self.new_evaluator(
                    &air,
                    aux_trace_rand_elements,
                    channel.get_constraint_composition_coeffs(),
                )
                .evaluate(&trace_lde, &domain)
            });
        assert_eq!(composition_poly_trace.num_rows(), ce_domain_size);

        // 3 ----- commit to constraint evaluations -----------------------------------------------
        let (constraint_commitment, composition_poly) = {
            let span = info_span!("commit_to_constraint_evaluations").entered();

            // first, build a commitment to the evaluations of the constraint composition
            // polynomial columns
            let (constraint_commitment, composition_poly) = self.build_constraint_commitment::<E>(
                composition_poly_trace,
                air.context().num_constraint_composition_columns(),
                &domain,
            );

            // then, commit to the evaluations of constraints by writing the root of the constraint
            // Merkle tree into the channel
            channel.commit_constraints(constraint_commitment.root());

            drop(span);
            (constraint_commitment, composition_poly)
        };

        // 4 ----- build DEEP composition polynomial ----------------------------------------------
        let deep_composition_poly = {
            let span = info_span!("build_deep_composition_poly").entered();
            // draw an out-of-domain point z. Depending on the type of E, the point is drawn either
            // from the base field or from an extension field defined by E.
            //
            // The purpose of sampling from the extension field here (instead of the base field) is
            // to increase security. Soundness is limited by the size of the field that the random
            // point is drawn from, and we can potentially save on performance by only drawing this
            // point from an extension field, rather than increasing the size of the field overall.
            let z = channel.get_ood_point();

            // evaluate trace and constraint polynomials at the OOD point z, and send the results to
            // the verifier. the trace polynomials are actually evaluated over two points: z and
            // z * g, where g is the generator of the trace domain.
            let ood_trace_states = trace_polys.get_ood_frame(z);
            channel.send_ood_trace_states(&ood_trace_states);

            let ood_evaluations = composition_poly.evaluate_at(z);
            channel.send_ood_constraint_evaluations(&ood_evaluations);

            // draw random coefficients to use during DEEP polynomial composition, and use them to
            // initialize the DEEP composition polynomial
            let deep_coefficients = channel.get_deep_composition_coeffs();
            let mut deep_composition_poly = DeepCompositionPoly::new(z, deep_coefficients);

            // combine all trace polynomials together and merge them into the DEEP composition
            // polynomial
            deep_composition_poly.add_trace_polys(trace_polys, ood_trace_states);

            // merge columns of constraint composition polynomial into the DEEP composition
            // polynomial
            deep_composition_poly.add_composition_poly(composition_poly, ood_evaluations);

            event!(Level::DEBUG, "degree: {}", deep_composition_poly.degree());

            drop(span);
            deep_composition_poly
        };

        // make sure the degree of the DEEP composition polynomial is equal to trace polynomial
        // degree minus 1.
        assert_eq!(trace_length - 2, deep_composition_poly.degree());

        // 5 ----- evaluate DEEP composition polynomial over LDE domain ---------------------------
        let deep_evaluations = {
            let span = info_span!("evaluate_deep_composition_poly").entered();
            let deep_evaluations = deep_composition_poly.evaluate(&domain);
            // we check the following condition in debug mode only because infer_degree is an
            // expensive operation
            debug_assert_eq!(trace_length - 2, infer_degree(&deep_evaluations, domain.offset()));

            drop(span);
            deep_evaluations
        };

        // 6 ----- compute FRI layers for the composition polynomial ------------------------------
        let fri_options = air.options().to_fri_options();
        let num_layers = fri_options.num_fri_layers(lde_domain_size);
        let mut fri_prover = FriProver::new(fri_options);
        info_span!("compute_fri_layers", num_layers)
            .in_scope(|| fri_prover.build_layers(&mut channel, deep_evaluations));

        // 7 ----- determine query positions ------------------------------------------------------
        let query_positions = {
            let grinding_factor = air.options().grinding_factor();
            let num_positions = air.options().num_queries();
            let span =
                info_span!("determine_query_positions", grinding_factor, num_positions,).entered();

            // apply proof-of-work to the query seed
            channel.grind_query_seed();

            // generate pseudo-random query positions
            let query_positions = channel.get_query_positions();
            event!(Level::DEBUG, "query_positions_len: {}", query_positions.len());

            drop(span);
            query_positions
        };

        // 8 ----- build proof object -------------------------------------------------------------
        let proof = {
            let span = info_span!("build_proof_object").entered();
            // generate FRI proof
            let fri_proof = fri_prover.build_proof(&query_positions);

            // query the execution trace at the selected position; for each query, we need the
            // state of the trace at that position + Merkle authentication path
            let trace_queries = trace_lde.query(&query_positions);

            // query the constraint commitment at the selected positions; for each query, we need
            // just a Merkle authentication path. this is because constraint evaluations for each
            // step are merged into a single value and Merkle authentication paths contain these
            // values already
            let constraint_queries = constraint_commitment.query(&query_positions);

            // build the proof object
            let proof = channel.build_proof(
                trace_queries,
                constraint_queries,
                fri_proof,
                query_positions.len(),
            );

            drop(span);
            proof
        };

        Ok(proof)
    }

    /// Extends constraint composition polynomial over the LDE domain and builds a commitment to
    /// its evaluations.
    ///
    /// The extension is done by first interpolating the evaluations of the polynomial so that we
    /// get the composition polynomial in coefficient form; then breaking the polynomial into
    /// columns each of size equal to trace length, and finally evaluating each composition
    /// polynomial column over the LDE domain.
    ///
    /// The commitment is computed by hashing each row in the evaluation matrix, and then building
    /// a Merkle tree from the resulting hashes.
    fn build_constraint_commitment<E>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (ConstraintCommitment<E, Self::HashFn>, CompositionPoly<E>)
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        // first, build constraint composition polynomial from its trace as follows:
        // - interpolate the trace into a polynomial in coefficient form
        // - "break" the polynomial into a set of column polynomials each of degree equal to
        //   trace_length - 1
        let composition_poly = info_span!(
            "build_composition_poly_columns",
            num_columns = num_constraint_composition_columns
        )
        .in_scope(|| {
            CompositionPoly::new(composition_poly_trace, domain, num_constraint_composition_columns)
        });
        assert_eq!(composition_poly.num_columns(), num_constraint_composition_columns);
        assert_eq!(composition_poly.column_degree(), domain.trace_length() - 1);

        // then, evaluate composition polynomial columns over the LDE domain
        let domain_size = domain.lde_domain_size();
        let composed_evaluations = info_span!("evaluate_composition_poly_columns").in_scope(|| {
            RowMatrix::evaluate_polys_over::<DEFAULT_SEGMENT_WIDTH>(composition_poly.data(), domain)
        });
        assert_eq!(composed_evaluations.num_cols(), num_constraint_composition_columns);
        assert_eq!(composed_evaluations.num_rows(), domain_size);

        // finally, build constraint evaluation commitment
        let constraint_commitment = info_span!(
            "compute_constraint_evaluation_commitment",
            tree_depth = domain_size.ilog2()
        )
        .in_scope(|| {
            let commitment = composed_evaluations.commit_to_rows();
            ConstraintCommitment::new(composed_evaluations, commitment)
        });
        assert_eq!(constraint_commitment.tree_depth(), domain_size.ilog2() as usize);

        (constraint_commitment, composition_poly)
    }
}
