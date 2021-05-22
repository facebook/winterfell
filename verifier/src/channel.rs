// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{errors::VerifierError, proof::StarkProof, Air, EvaluationFrame};
use crypto::{BatchMerkleProof, Hasher, MerkleTree};
use fri::VerifierChannel as FriVerifierChannel;
use math::field::{FieldElement, StarkField};

// TYPES AND INTERFACES
// ================================================================================================

pub struct VerifierChannel<B: StarkField, E: FieldElement + From<B>, H: Hasher> {
    // trace queries
    trace_root: H::Digest,
    trace_proof: BatchMerkleProof<H>,
    trace_states: Vec<Vec<B>>,
    // constraint queries
    constraint_root: H::Digest,
    constraint_proof: BatchMerkleProof<H>,
    constraint_evaluations: Vec<Vec<E>>,
    // FRI proof
    fri_roots: Vec<H::Digest>,
    fri_layer_proofs: Vec<BatchMerkleProof<H>>,
    fri_layer_queries: Vec<Vec<E>>,
    fri_remainder: Vec<E>,
    fri_partitioned: bool,
    // out-of-domain evaluation
    ood_frame: EvaluationFrame<E>,
    ood_evaluations: Vec<E>,
    // query proof-of-work
    pow_nonce: u64,
}

// VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<B: StarkField, E: FieldElement + From<B>, H: Hasher> VerifierChannel<B, E, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates and returns a new verifier channel initialized from the specified `proof`.
    pub fn new<A: Air<BaseElement = B>>(air: &A, proof: StarkProof) -> Result<Self, VerifierError> {
        // make AIR and proof base fields are the same
        if B::get_modulus_le_bytes() != proof.context.field_modulus_bytes() {
            return Err(VerifierError::InconsistentBaseField);
        }

        let lde_domain_size = air.lde_domain_size();
        let num_queries = air.options().num_queries();
        let fri_options = air.options().to_fri_options::<B>();

        // --- parse commitments ------------------------------------------------------------------
        let (trace_root, constraint_root, fri_roots) = proof
            .commitments
            .parse::<H>(fri_options.num_fri_layers(lde_domain_size))
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse trace queries ----------------------------------------------------------------
        let (trace_proof, trace_states) = proof
            .trace_queries
            .parse::<H, B>(lde_domain_size, num_queries, air.trace_width())
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "trace query deserialization failed: {}",
                    err.to_string()
                ))
            })?;

        // --- parse constraint evaluation queries ------------------------------------------------
        let (constraint_proof, constraint_evaluations) = proof
            .constraint_queries
            .parse::<H, E>(lde_domain_size, num_queries, air.ce_blowup_factor())
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "constraint evaluation query deserialization failed: {}",
                    err.to_string()
                ))
            })?;

        // --- parse FRI proofs -------------------------------------------------------------------
        let fri_partitioned = proof.fri_proof.is_partitioned();
        let fri_remainder = proof
            .fri_proof
            .parse_remainder()
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;
        let (fri_layer_queries, fri_layer_proofs) = proof
            .fri_proof
            .parse_layers::<H, E>(lde_domain_size, fri_options.folding_factor())
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse out-of-domain evaluation frame -----------------------------------------------
        let (ood_frame, ood_evaluations) = proof
            .ood_frame
            .parse(air.trace_width(), air.ce_blowup_factor())
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        Ok(VerifierChannel {
            // trace queries
            trace_root,
            trace_proof,
            trace_states,
            // constraint queries
            constraint_root,
            constraint_proof,
            constraint_evaluations,
            // FRI proof
            fri_roots,
            fri_layer_proofs,
            fri_layer_queries,
            fri_remainder,
            fri_partitioned,
            // out-of-domain evaluation
            ood_frame,
            ood_evaluations,
            // query seed
            pow_nonce: proof.pow_nonce,
        })
    }

    // DATA READERS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace commitment sent by the prover.
    pub fn read_trace_commitment(&self) -> H::Digest {
        self.trace_root
    }

    /// Returns constraint evaluation commitment sent by the prover.
    pub fn read_constraint_commitment(&self) -> H::Digest {
        self.constraint_root
    }

    /// Returns trace polynomial evaluations at out-of-domain points z and z * g, where g is the
    /// generator of the LDE domain.
    pub fn read_ood_evaluation_frame(&self) -> &EvaluationFrame<E> {
        &self.ood_frame
    }

    /// Returns evaluations of composition polynomial columns at z^m, where z is the out-of-domain
    /// point, and m is the number of composition polynomial columns.
    pub fn read_ood_evaluations(&self) -> &[E] {
        &self.ood_evaluations
    }

    /// Returns commitments to FRI layers sent by the prover.
    pub fn read_fri_layer_commitments(&self) -> &[H::Digest] {
        &self.fri_roots
    }

    /// Returns query proof-of-work nonce sent by the prover.
    pub fn read_pow_nonce(&self) -> u64 {
        self.pow_nonce
    }

    /// Returns trace states at the specified positions of the LDE domain. This also checks if
    /// the trace states are valid against the trace commitment sent by the prover.
    pub fn read_trace_states(
        &self,
        positions: &[usize],
        commitment: &H::Digest,
    ) -> Result<&[Vec<B>], VerifierError> {
        // make sure the states included in the proof correspond to the trace commitment
        if !MerkleTree::verify_batch(commitment, positions, &self.trace_proof) {
            return Err(VerifierError::TraceQueryDoesNotMatchCommitment);
        }

        Ok(&self.trace_states)
    }

    /// Returns constraint evaluations at the specified positions of the LDE domain. This also
    /// checks if the constraint evaluations are valid against the constraint commitment sent by
    /// the prover.
    pub fn read_constraint_evaluations(
        &self,
        positions: &[usize],
        commitment: &H::Digest,
    ) -> Result<&[Vec<E>], VerifierError> {
        if !MerkleTree::verify_batch(commitment, &positions, &self.constraint_proof) {
            return Err(VerifierError::ConstraintQueryDoesNotMatchCommitment);
        }

        Ok(&self.constraint_evaluations)
    }
}

// FRI VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<B, E, H> FriVerifierChannel<E> for VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    H: Hasher,
{
    type Hasher = H;

    fn fri_layer_commitments(&self) -> &[H::Digest] {
        &self.fri_roots
    }

    fn fri_layer_proofs(&self) -> &[BatchMerkleProof<H>] {
        &self.fri_layer_proofs
    }

    fn fri_layer_queries(&self) -> &[Vec<E>] {
        &self.fri_layer_queries
    }

    fn fri_remainder(&self) -> &[E] {
        &self.fri_remainder
    }

    fn fri_partitioned(&self) -> bool {
        self.fri_partitioned
    }
}
