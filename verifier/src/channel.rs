// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{string::ToString, vec::Vec};

use air::{
    proof::{Proof, Queries, Table, TraceOodFrame},
    Air,
};
use crypto::{BatchMerkleProof, ElementHasher, MerkleTree};
use fri::VerifierChannel as FriVerifierChannel;
use math::{FieldElement, StarkField};

use crate::VerifierError;

// VERIFIER CHANNEL
// ================================================================================================

/// A view into a [Proof] for a computation structured to simulate an "interactive" channel.
///
/// A channel is instantiated for a specific proof, which is parsed into structs over the
/// appropriate field (specified by type parameter `E`). This also validates that the proof is
/// well-formed in the context of the computation for the specified [Air].
pub struct VerifierChannel<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    // trace queries
    trace_roots: Vec<H::Digest>,
    trace_queries: Option<TraceQueries<E, H>>,
    // constraint queries
    constraint_root: H::Digest,
    constraint_queries: Option<ConstraintQueries<E, H>>,
    // FRI proof
    fri_roots: Option<Vec<H::Digest>>,
    fri_layer_proofs: Vec<BatchMerkleProof<H>>,
    fri_layer_queries: Vec<Vec<E>>,
    fri_remainder: Option<Vec<E>>,
    fri_num_partitions: usize,
    // out-of-domain frame
    ood_trace_frame: Option<TraceOodFrame<E>>,
    ood_constraint_evaluations: Option<Vec<E>>,
    // query proof-of-work
    pow_nonce: u64,
    gkr_proof: Option<Vec<u8>>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> VerifierChannel<E, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates and returns a new [VerifierChannel] initialized from the specified `proof`.
    pub fn new<A: Air<BaseField = E::BaseField>>(
        air: &A,
        proof: Proof,
    ) -> Result<Self, VerifierError> {
        let Proof {
            context,
            num_unique_queries,
            commitments,
            trace_queries,
            constraint_queries,
            ood_frame,
            fri_proof,
            pow_nonce,
            gkr_proof,
        } = proof;

        // make sure AIR and proof base fields are the same
        if E::BaseField::get_modulus_le_bytes() != context.field_modulus_bytes() {
            return Err(VerifierError::InconsistentBaseField);
        }
        let constraint_frame_width = air.context().num_constraint_composition_columns();

        let num_trace_segments = air.trace_info().num_segments();
        let main_trace_width = air.trace_info().main_trace_width();
        let aux_trace_width = air.trace_info().aux_segment_width();
        let lde_domain_size = air.lde_domain_size();
        let fri_options = air.options().to_fri_options();

        // --- parse commitments ------------------------------------------------------------------
        let (trace_roots, constraint_root, fri_roots) = commitments
            .parse::<H>(num_trace_segments, fri_options.num_fri_layers(lde_domain_size))
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse trace and constraint queries -------------------------------------------------
        let trace_queries = TraceQueries::new(trace_queries, air, num_unique_queries as usize)?;
        let constraint_queries =
            ConstraintQueries::new(constraint_queries, air, num_unique_queries as usize)?;

        // --- parse FRI proofs -------------------------------------------------------------------
        let fri_num_partitions = fri_proof.num_partitions();
        let fri_remainder = fri_proof
            .parse_remainder()
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;
        let (fri_layer_queries, fri_layer_proofs) = fri_proof
            .parse_layers::<H, E>(lde_domain_size, fri_options.folding_factor())
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse out-of-domain evaluation frame -----------------------------------------------
        let (ood_trace_frame, ood_constraint_evaluations) = ood_frame
            .parse(main_trace_width, aux_trace_width, constraint_frame_width)
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        Ok(VerifierChannel {
            // trace queries
            trace_roots,
            trace_queries: Some(trace_queries),
            // constraint queries
            constraint_root,
            constraint_queries: Some(constraint_queries),
            // FRI proof
            fri_roots: Some(fri_roots),
            fri_layer_proofs,
            fri_layer_queries,
            fri_remainder: Some(fri_remainder),
            fri_num_partitions,
            // out-of-domain evaluation
            ood_trace_frame: Some(ood_trace_frame),
            ood_constraint_evaluations: Some(ood_constraint_evaluations),
            // query seed
            pow_nonce,
            gkr_proof,
        })
    }

    // DATA READERS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace commitments sent by the prover.
    ///
    /// For computations requiring multiple trace segment, the returned slice will contain a
    /// commitment for each trace segment.
    pub fn read_trace_commitments(&self) -> &[H::Digest] {
        &self.trace_roots
    }

    /// Returns constraint evaluation commitment sent by the prover.
    pub fn read_constraint_commitment(&self) -> H::Digest {
        self.constraint_root
    }

    /// Returns trace polynomial evaluations at out-of-domain points z and z * g, where g is the
    /// generator of the LDE domain.
    ///
    /// For computations requiring multiple trace segments, evaluations of auxiliary trace
    /// polynomials are also included.
    pub fn read_ood_trace_frame(&mut self) -> TraceOodFrame<E> {
        self.ood_trace_frame.take().expect("already read")
    }

    /// Returns evaluations of composition polynomial columns at z^m, where z is the out-of-domain
    /// point, and m is the number of composition polynomial columns.
    pub fn read_ood_constraint_evaluations(&mut self) -> Vec<E> {
        self.ood_constraint_evaluations.take().expect("already read")
    }

    /// Returns query proof-of-work nonce sent by the prover.
    pub fn read_pow_nonce(&self) -> u64 {
        self.pow_nonce
    }

    /// Returns the serialized GKR proof, if any.
    pub fn read_gkr_proof(&self) -> Option<&Vec<u8>> {
        self.gkr_proof.as_ref()
    }

    /// Returns trace states at the specified positions of the LDE domain. This also checks if
    /// the trace states are valid against the trace commitment sent by the prover.
    ///
    /// For computations requiring multiple trace segments, trace states for auxiliary segments
    /// are also included as the second value of the returned tuple (trace states for all auxiliary
    /// segments are merged into a single table). Otherwise, the second value is None.
    #[allow(clippy::type_complexity)]
    pub fn read_queried_trace_states(
        &mut self,
        positions: &[usize],
    ) -> Result<(Table<E::BaseField>, Option<Table<E>>), VerifierError> {
        let queries = self.trace_queries.take().expect("already read");

        // make sure the states included in the proof correspond to the trace commitment
        for (root, proof) in self.trace_roots.iter().zip(queries.query_proofs.iter()) {
            MerkleTree::verify_batch(root, positions, proof)
                .map_err(|_| VerifierError::TraceQueryDoesNotMatchCommitment)?;
        }

        Ok((queries.main_states, queries.aux_states))
    }

    /// Returns constraint evaluations at the specified positions of the LDE domain. This also
    /// checks if the constraint evaluations are valid against the constraint commitment sent by
    /// the prover.
    pub fn read_constraint_evaluations(
        &mut self,
        positions: &[usize],
    ) -> Result<Table<E>, VerifierError> {
        let queries = self.constraint_queries.take().expect("already read");

        MerkleTree::verify_batch(&self.constraint_root, positions, &queries.query_proofs)
            .map_err(|_| VerifierError::ConstraintQueryDoesNotMatchCommitment)?;

        Ok(queries.evaluations)
    }
}

// FRI VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<E, H> FriVerifierChannel<E> for VerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    type Hasher = H;

    fn read_fri_num_partitions(&self) -> usize {
        self.fri_num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<H::Digest> {
        self.fri_roots.take().expect("already read")
    }

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<H> {
        self.fri_layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<E> {
        self.fri_layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<E> {
        self.fri_remainder.take().expect("already read")
    }
}

// TRACE QUERIES
// ================================================================================================

/// Container of trace query data, including:
/// * Queried states for all trace segments.
/// * Merkle authentication paths for all queries.
///
/// Trace states for all auxiliary segments are stored in a single table.
struct TraceQueries<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    query_proofs: Vec<BatchMerkleProof<H>>,
    main_states: Table<E::BaseField>,
    aux_states: Option<Table<E>>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> TraceQueries<E, H> {
    /// Parses the provided trace queries into trace states in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new<A: Air<BaseField = E::BaseField>>(
        mut queries: Vec<Queries>,
        air: &A,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        assert_eq!(
            queries.len(),
            air.trace_info().num_segments(),
            "expected {} trace segment queries, but received {}",
            air.trace_info().num_segments(),
            queries.len()
        );

        // parse main trace segment queries; parsing also validates that hashes of each table row
        // form the leaves of Merkle authentication paths in the proofs
        let main_segment_width = air.trace_info().main_trace_width();
        let main_segment_queries = queries.remove(0);
        let (main_segment_query_proofs, main_segment_states) = main_segment_queries
            .parse::<H, E::BaseField>(air.lde_domain_size(), num_queries, main_segment_width)
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "main trace segment query deserialization failed: {err}"
                ))
            })?;

        // all query proofs will be aggregated into a single vector
        let mut query_proofs = vec![main_segment_query_proofs];

        // parse auxiliary trace segment queries (if any), and merge resulting tables into a
        // single table; parsing also validates that hashes of each table row form the leaves
        // of Merkle authentication paths in the proofs
        let aux_trace_states = if air.trace_info().is_multi_segment() {
            let mut aux_trace_states = Vec::new();
            let segment_queries = queries.remove(0);
            let segment_width = air.trace_info().get_aux_segment_width();
            let (segment_query_proof, segment_trace_states) = segment_queries
                .parse::<H, E>(air.lde_domain_size(), num_queries, segment_width)
                .map_err(|err| {
                    VerifierError::ProofDeserializationError(format!(
                        "auxiliary trace segment query deserialization failed: {err}"
                    ))
                })?;

            query_proofs.push(segment_query_proof);
            aux_trace_states.push(segment_trace_states);

            // merge tables for each auxiliary segment into a single table
            Some(Table::merge(aux_trace_states))
        } else {
            None
        };

        Ok(Self {
            query_proofs,
            main_states: main_segment_states,
            aux_states: aux_trace_states,
        })
    }
}

// CONSTRAINT QUERIES
// ================================================================================================

/// Container of constraint evaluation query data, including:
/// * Queried constraint evaluation values.
/// * Merkle authentication paths for all queries.
struct ConstraintQueries<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    query_proofs: BatchMerkleProof<H>,
    evaluations: Table<E>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> ConstraintQueries<E, H> {
    /// Parses the provided constraint queries into evaluations in the specified field and
    /// corresponding Merkle authentication paths.
    pub fn new<A: Air<BaseField = E::BaseField>>(
        queries: Queries,
        air: &A,
        num_queries: usize,
    ) -> Result<Self, VerifierError> {
        let constraint_frame_width = air.context().num_constraint_composition_columns();

        let (query_proofs, evaluations) = queries
            .parse::<H, E>(air.lde_domain_size(), num_queries, constraint_frame_width)
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "constraint evaluation query deserialization failed: {err}"
                ))
            })?;

        Ok(Self { query_proofs, evaluations })
    }
}
