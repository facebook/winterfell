// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{
    errors::VerifierError,
    proof::{Commitments, OodEvaluationFrame, Queries, StarkProof},
    utils, Air, ComputationContext, EvaluationFrame, ProofOptions, PublicCoin,
};
use crypto::{BatchMerkleProof, Hasher, MerkleTree};
use fri::{PublicCoin as FriPublicCoin, VerifierChannel as FriVerifierChannel};
use math::{
    field::{FieldElement, StarkField},
    utils::read_elements_into_vec,
};
use std::convert::TryInto;
use std::marker::PhantomData;

// TYPES AND INTERFACES
// ================================================================================================

pub struct VerifierChannel<B: StarkField, E: FieldElement + From<B>, H: Hasher> {
    context: ComputationContext,
    commitments: Commitments,
    trace_queries: Queries,
    constraint_queries: Queries,
    ood_frame: OodEvaluationFrame,
    fri_layer_proofs: Vec<BatchMerkleProof>,
    fri_layer_queries: Vec<Vec<E>>,
    fri_remainder: Vec<E>,
    fri_partitioned: bool,
    query_seed: [u8; 32],
    _base_element: PhantomData<B>,
    _hasher: PhantomData<H>,
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
        let query_seed = build_query_seed::<H>(
            &proof.commitments.fri_roots,
            proof.pow_nonce,
            &air.context().options(),
        )?;

        Ok(VerifierChannel {
            context: air.context().clone(),
            commitments: proof.commitments,
            ood_frame: proof.ood_frame,
            trace_queries: proof.trace_queries,
            constraint_queries: proof.constraint_queries,
            fri_layer_proofs,
            fri_layer_queries,
            fri_remainder,
            fri_partitioned,
            query_seed,
            _base_element: PhantomData,
            _hasher: PhantomData,
        })
    }

    /// Returns trace polynomial evaluations at OOD points z and z * g, where g is the generator
    /// of the LDE domain.
    pub fn read_ood_frame(&self) -> Result<EvaluationFrame<E>, VerifierError> {
        let current = match read_elements_into_vec(&self.ood_frame.trace_at_z1) {
            Ok(elements) => {
                if elements.len() != self.context.trace_width() {
                    return Err(VerifierError::OodFrameDeserializationFailed);
                }
                elements
            }
            Err(_) => return Err(VerifierError::OodFrameDeserializationFailed),
        };
        let next = match read_elements_into_vec(&self.ood_frame.trace_at_z2) {
            Ok(elements) => {
                if elements.len() != self.context.trace_width() {
                    return Err(VerifierError::OodFrameDeserializationFailed);
                }
                elements
            }
            Err(_) => return Err(VerifierError::OodFrameDeserializationFailed),
        };

        Ok(EvaluationFrame { current, next })
    }

    /// Returns trace states at the specified positions. This also checks if the
    /// trace states are valid against the trace commitment sent by the prover.
    pub fn read_trace_states(&self, positions: &[usize]) -> Result<Vec<Vec<B>>, VerifierError> {
        // deserialize query bytes into a set of trace states at the specified positions
        // and corresponding Merkle paths
        // TODO: avoid cloning
        let (merkle_paths, trace_states) = self
            .trace_queries
            .clone()
            .deserialize::<H, B>(self.context.lde_domain_size(), self.context.trace_width())
            .map_err(|_err| VerifierError::TraceQueryDeserializationFailed)?;

        // make sure the states included in the proof correspond to the trace commitment
        if !MerkleTree::verify_batch(
            &self.commitments.trace_root,
            positions,
            &merkle_paths,
            H::hash_fn(),
        ) {
            return Err(VerifierError::TraceQueryDoesNotMatchCommitment);
        }

        Ok(trace_states)
    }

    /// Returns constraint evaluations at the specified positions. This also checks if the
    /// constraint evaluations are valid against the constraint commitment sent by the prover.
    pub fn read_constraint_evaluations(
        &self,
        positions: &[usize],
    ) -> Result<Vec<E>, VerifierError> {
        let evaluations_per_leaf = utils::evaluations_per_leaf::<E, H>();
        let num_leaves = self.context.lde_domain_size() / evaluations_per_leaf;
        // deserialize query bytes into a set of constraint evaluations at the specified positions
        // and corresponding Merkle paths
        // TODO: avoid cloning
        let (merkle_paths, constraint_evaluations) = self
            .constraint_queries
            .clone()
            .deserialize::<H, E>(num_leaves, evaluations_per_leaf)
            .map_err(|_err| VerifierError::ConstraintQueryDeserializationFailed)?;

        let c_positions = utils::map_trace_to_constraint_positions(positions, evaluations_per_leaf);
        if !MerkleTree::verify_batch(
            &self.commitments.constraint_root,
            &c_positions,
            &merkle_paths,
            H::hash_fn(),
        ) {
            return Err(VerifierError::ConstraintQueryDoesNotMatchCommitment);
        }

        // build constraint evaluation values from the leaves of constraint Merkle proof
        let mut evaluations: Vec<E> = Vec::with_capacity(positions.len());
        for &position in positions.iter() {
            // TODO: position computation should be in common
            let leaf_idx = c_positions
                .iter()
                .position(|&v| v == position / evaluations_per_leaf)
                .unwrap();
            evaluations.push(constraint_evaluations[leaf_idx][position % evaluations_per_leaf]);
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
    fn fri_layer_proofs(&self) -> &[BatchMerkleProof] {
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

    fn constraint_seed(&self) -> [u8; 32] {
        self.commitments.trace_root
    }

    fn composition_seed(&self) -> [u8; 32] {
        self.commitments.constraint_root
    }

    fn query_seed(&self) -> [u8; 32] {
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

    fn fri_layer_commitments(&self) -> &[[u8; 32]] {
        &self.commitments.fri_roots
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_query_seed<H: Hasher>(
    fri_roots: &[[u8; 32]],
    nonce: u64,
    options: &ProofOptions,
) -> Result<[u8; 32], VerifierError> {
    let hash_fn = H::hash_fn();

    // combine roots of all FIR layers into a single array of bytes
    let mut root_bytes: Vec<u8> = Vec::with_capacity(fri_roots.len() * 32);
    for root in fri_roots.iter() {
        root.iter().for_each(|&v| root_bytes.push(v));
    }

    // hash the array of bytes into a single 32-byte value
    let mut query_seed = [0u8; 32];
    hash_fn(&root_bytes, &mut query_seed);

    // verify proof of work
    let mut input_bytes = [0; 64];
    input_bytes[0..32].copy_from_slice(&query_seed);
    input_bytes[56..].copy_from_slice(&nonce.to_le_bytes());

    hash_fn(&input_bytes, &mut query_seed);

    let seed_head = u64::from_le_bytes(query_seed[..8].try_into().unwrap());
    if seed_head.trailing_zeros() < options.grinding_factor() {
        return Err(VerifierError::QuerySeedProofOfWorkVerificationFailed);
    }

    Ok(query_seed)
}
