// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::VerifierError;
use air::{proof::StarkProof, Air, EvaluationFrame};
use crypto::{BatchMerkleProof, ElementHasher, MerkleTree};
use fri::VerifierChannel as FriVerifierChannel;
use math::{FieldElement, StarkField};
use utils::{collections::Vec, string::ToString};

// TYPES AND INTERFACES
// ================================================================================================

pub struct VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
{
    // trace queries
    trace_root: H::Digest,
    trace_proof: BatchMerkleProof<H>,
    trace_states: Option<Vec<Vec<B>>>,
    // constraint queries
    constraint_root: H::Digest,
    constraint_proof: BatchMerkleProof<H>,
    constraint_evaluations: Option<Vec<Vec<E>>>,
    // FRI proof
    fri_roots: Option<Vec<H::Digest>>,
    fri_layer_proofs: Vec<BatchMerkleProof<H>>,
    fri_layer_queries: Vec<Vec<E>>,
    fri_remainder: Option<Vec<E>>,
    fri_num_partitions: usize,
    // out-of-domain evaluation
    ood_frame: Option<EvaluationFrame<E>>,
    ood_evaluations: Option<Vec<E>>,
    // query proof-of-work
    pow_nonce: u64,
}

// VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<B, E, H> VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates and returns a new verifier channel initialized from the specified `proof`.
    pub fn new<A: Air<BaseField = B>>(air: &A, proof: StarkProof) -> Result<Self, VerifierError> {
        // make AIR and proof base fields are the same
        if B::get_modulus_le_bytes() != proof.context.field_modulus_bytes() {
            return Err(VerifierError::InconsistentBaseField);
        }

        let lde_domain_size = air.lde_domain_size();
        let num_queries = air.options().num_queries();
        let fri_options = air.options().to_fri_options();

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
                    err
                ))
            })?;

        // --- parse constraint evaluation queries ------------------------------------------------
        let (constraint_proof, constraint_evaluations) = proof
            .constraint_queries
            .parse::<H, E>(lde_domain_size, num_queries, air.ce_blowup_factor())
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "constraint evaluation query deserialization failed: {}",
                    err
                ))
            })?;

        // --- parse FRI proofs -------------------------------------------------------------------
        let fri_num_partitions = proof.fri_proof.num_partitions();
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
            trace_states: Some(trace_states),
            // constraint queries
            constraint_root,
            constraint_proof,
            constraint_evaluations: Some(constraint_evaluations),
            // FRI proof
            fri_roots: Some(fri_roots),
            fri_layer_proofs,
            fri_layer_queries,
            fri_remainder: Some(fri_remainder),
            fri_num_partitions,
            // out-of-domain evaluation
            ood_frame: Some(ood_frame),
            ood_evaluations: Some(ood_evaluations),
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
    pub fn read_ood_evaluation_frame(&mut self) -> EvaluationFrame<E> {
        self.ood_frame.take().expect("already read")
    }

    /// Returns evaluations of composition polynomial columns at z^m, where z is the out-of-domain
    /// point, and m is the number of composition polynomial columns.
    pub fn read_ood_evaluations(&mut self) -> Vec<E> {
        self.ood_evaluations.take().expect("already read")
    }

    /// Returns query proof-of-work nonce sent by the prover.
    pub fn read_pow_nonce(&self) -> u64 {
        self.pow_nonce
    }

    /// Returns trace states at the specified positions of the LDE domain. This also checks if
    /// the trace states are valid against the trace commitment sent by the prover.
    pub fn read_trace_states(
        &mut self,
        positions: &[usize],
        commitment: &H::Digest,
    ) -> Result<Vec<Vec<B>>, VerifierError> {
        // make sure the states included in the proof correspond to the trace commitment
        MerkleTree::verify_batch(commitment, positions, &self.trace_proof)
            .map_err(|_| VerifierError::TraceQueryDoesNotMatchCommitment)?;

        Ok(self.trace_states.take().expect("already read"))
    }

    /// Returns constraint evaluations at the specified positions of the LDE domain. This also
    /// checks if the constraint evaluations are valid against the constraint commitment sent by
    /// the prover.
    pub fn read_constraint_evaluations(
        &mut self,
        positions: &[usize],
        commitment: &H::Digest,
    ) -> Result<Vec<Vec<E>>, VerifierError> {
        MerkleTree::verify_batch(commitment, positions, &self.constraint_proof)
            .map_err(|_| VerifierError::ConstraintQueryDoesNotMatchCommitment)?;

        Ok(self.constraint_evaluations.take().expect("already read"))
    }
}

// FRI VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<B, E, H> FriVerifierChannel<E> for VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
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
