// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{
    errors::VerifierError, proof::StarkProof, utils, Air, ComputationContext, EvaluationFrame,
    ProofOptions, PublicCoin,
};
use crypto::{BatchMerkleProof, Hasher, MerkleTree};
use fri::{PublicCoin as FriPublicCoin, VerifierChannel as FriVerifierChannel};
use math::field::{FieldElement, StarkField};
use std::convert::TryInto;

// TYPES AND INTERFACES
// ================================================================================================

pub struct VerifierChannel<B: StarkField, E: FieldElement + From<B>, H: Hasher> {
    context: ComputationContext,
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
    // query seed
    query_seed: H::Digest,
    // out-of-domain evaluation frame
    ood_frame: EvaluationFrame<E>,
}

// VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<B, E, H> VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    H: Hasher,
{
    /// Creates and returns a new verifier channel initialized from the specified `proof`.
    pub fn new<A: Air<BaseElement = B>>(air: &A, proof: StarkProof) -> Result<Self, VerifierError> {
        // TODO: validate field modulus
        // TODO: verify ce blowup factor

        // --- parse commitments ------------------------------------------------------------------
        let fri_options = air.context().options().to_fri_options::<B>();
        let num_fri_layers = fri_options.num_fri_layers(air.lde_domain_size());
        let (trace_root, constraint_root, fri_roots) = proof
            .commitments
            .parse::<H>(num_fri_layers)
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- parse trace queries ----------------------------------------------------------------
        let (trace_proof, trace_states) = proof
            .trace_queries
            .parse::<H, B>(air.lde_domain_size(), air.trace_width())
            .map_err(|err| {
                VerifierError::ProofDeserializationError(format!(
                    "trace query deserialization failed: {}",
                    err.to_string()
                ))
            })?;

        // --- parse constraint evaluation queries ------------------------------------------------
        let evaluations_per_leaf = utils::evaluations_per_leaf::<E, H>();
        let num_leaves = air.lde_domain_size() / evaluations_per_leaf;
        let (constraint_proof, constraint_evaluations) = proof
            .constraint_queries
            .parse::<H, E>(num_leaves, evaluations_per_leaf)
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
        // TODO: don't hard-code folding factor
        let (fri_layer_queries, fri_layer_proofs) = proof
            .fri_proof
            .parse_layers::<H, E>(air.lde_domain_size(), 4)
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        // --- build query seed -------------------------------------------------------------------
        let query_seed =
            build_query_seed::<H>(&fri_roots, proof.pow_nonce, &air.context().options())?;

        // --- parse out-of-domain evaluation frame -----------------------------------------------
        let ood_frame = proof
            .ood_frame
            .parse(air.trace_width())
            .map_err(|err| VerifierError::ProofDeserializationError(err.to_string()))?;

        Ok(VerifierChannel {
            context: air.context().clone(),
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
            // query seed
            query_seed,
            // out-of-domain evaluation frame
            ood_frame,
        })
    }

    /// Returns trace polynomial evaluations at out-of-domain points z and z * g, where
    /// g is the generator of the LDE domain.
    pub fn read_ood_frame(&self) -> &EvaluationFrame<E> {
        &self.ood_frame
    }

    /// Returns trace states at the specified positions. This also checks if the
    /// trace states are valid against the trace commitment sent by the prover.
    pub fn read_trace_states(&self, positions: &[usize]) -> Result<&[Vec<B>], VerifierError> {
        // make sure the states included in the proof correspond to the trace commitment
        if !MerkleTree::verify_batch(&self.trace_root, positions, &self.trace_proof) {
            return Err(VerifierError::TraceQueryDoesNotMatchCommitment);
        }

        Ok(&self.trace_states)
    }

    /// Returns constraint evaluations at the specified positions. This also checks if the
    /// constraint evaluations are valid against the constraint commitment sent by the prover.
    pub fn read_constraint_evaluations(
        &self,
        positions: &[usize],
    ) -> Result<Vec<E>, VerifierError> {
        let evaluations_per_leaf = utils::evaluations_per_leaf::<E, H>();
        let c_positions = utils::map_trace_to_constraint_positions(positions, evaluations_per_leaf);
        if !MerkleTree::verify_batch(&self.constraint_root, &c_positions, &self.constraint_proof) {
            return Err(VerifierError::ConstraintQueryDoesNotMatchCommitment);
        }

        // build constraint evaluation values from the leaves of constraint Merkle proof
        let mut evaluations: Vec<E> = Vec::with_capacity(positions.len());
        for &position in positions.iter() {
            let leaf_idx = c_positions
                .iter()
                .position(|&v| v == position / evaluations_per_leaf)
                .unwrap();
            evaluations
                .push(self.constraint_evaluations[leaf_idx][position % evaluations_per_leaf]);
        }

        Ok(evaluations)
    }
}

impl<B, E, H> FriVerifierChannel<E> for VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    H: Hasher,
{
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

// PUBLIC COIN IMPLEMENTATIONS
// ================================================================================================
impl<B, E, H> PublicCoin for VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    H: Hasher,
{
    fn context(&self) -> &ComputationContext {
        &self.context
    }

    fn constraint_seed(&self) -> H::Digest {
        self.trace_root
    }

    fn composition_seed(&self) -> H::Digest {
        self.constraint_root
    }

    fn query_seed(&self) -> H::Digest {
        self.query_seed
    }
}

impl<B, E, H> FriPublicCoin for VerifierChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    H: Hasher,
{
    type Hasher = H;

    fn fri_layer_commitments(&self) -> &[H::Digest] {
        &self.fri_roots
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_query_seed<H: Hasher>(
    fri_roots: &[H::Digest],
    nonce: u64,
    options: &ProofOptions,
) -> Result<H::Digest, VerifierError> {
    // merge all FRI roots into a single value
    let merged_roots = H::merge_many(fri_roots);

    // verify proof of work
    let query_seed = H::merge_with_int(merged_roots, nonce);
    let seed_bytes: &[u8] = query_seed.as_ref();

    let seed_head = u64::from_le_bytes(seed_bytes[..8].try_into().unwrap());
    if seed_head.trailing_zeros() < options.grinding_factor() {
        return Err(VerifierError::QuerySeedProofOfWorkVerificationFailed);
    }

    Ok(query_seed)
}
