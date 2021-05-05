// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{folding::quartic, FriProof, ProofSerializationError, PublicCoin, VerifierError};
use core::marker::PhantomData;
use crypto::{BatchMerkleProof, Hasher, MerkleTree};
use math::field::FieldElement;
use utils::group_vector_elements;

// VERIFIER CHANNEL TRAIT
// ================================================================================================

pub trait VerifierChannel<E: FieldElement>: PublicCoin {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    fn fri_layer_proofs(&self) -> &[BatchMerkleProof];
    fn fri_layer_queries(&self) -> &[Vec<E>];
    fn fri_remainder(&self) -> &[E];
    fn fri_partitioned(&self) -> bool;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns FRI query values at the specified positions from the FRI layer at the
    /// specified index. This also checks if the values are valid against the FRI layer
    /// commitment sent by the prover.
    fn read_layer_queries<const N: usize>(
        &self,
        layer_idx: usize,
        positions: &[usize],
    ) -> Result<Vec<[E; N]>, VerifierError> {
        let hash_fn = Self::Hasher::hash_fn();
        let layer_root = self.fri_layer_commitments()[layer_idx];
        let layer_proof = &self.fri_layer_proofs()[layer_idx];

        if !MerkleTree::verify_batch(&layer_root, &positions, &layer_proof, hash_fn) {
            return Err(VerifierError::LayerCommitmentMismatch(layer_idx));
        }

        // TODO: avoid cloning
        let layer_queries = self.fri_layer_queries()[layer_idx].to_vec();
        Ok(group_vector_elements(layer_queries))
    }

    /// Reads FRI remainder values (last FRI layer). This also checks that the remainder is
    /// valid against the commitment sent by the prover.
    fn read_remainder(&self) -> Result<Vec<E>, VerifierError> {
        let hash_fn = Self::Hasher::hash_fn();

        // TODO: avoid cloning
        let remainder = self.fri_remainder().to_vec();

        // build remainder Merkle tree
        let remainder_values = quartic::transpose(&remainder, 1);
        let hashed_values = quartic::hash_values(&remainder_values, hash_fn);
        let remainder_tree = MerkleTree::new(hashed_values, hash_fn);

        // make sure the root of the tree matches the committed root of the last layer
        let committed_root = self.fri_layer_commitments().last().unwrap();
        if committed_root != remainder_tree.root() {
            return Err(VerifierError::RemainderCommitmentMismatch);
        }

        Ok(remainder)
    }

    fn num_fri_partitions(&self) -> usize {
        if self.fri_partitioned() {
            self.fri_remainder().len()
        } else {
            1
        }
    }
}

// DEFAULT VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

pub struct DefaultVerifierChannel<E: FieldElement, H: Hasher> {
    commitments: Vec<[u8; 32]>,
    layer_proofs: Vec<BatchMerkleProof>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    partitioned: bool,
    _hasher: PhantomData<H>,
}

impl<E: FieldElement, H: Hasher> DefaultVerifierChannel<E, H> {
    /// Builds a new verifier channel from the specified parameters.
    pub fn new(
        proof: FriProof,
        commitments: Vec<[u8; 32]>,
        domain_size: usize,
    ) -> Result<Self, ProofSerializationError> {
        let partitioned = proof.is_partitioned();

        let remainder = proof.parse_remainder()?;
        // TODO: don't hard-code folding factor
        let (layer_queries, layer_proofs) = proof.parse_layers::<H, E>(domain_size, 4)?;

        Ok(DefaultVerifierChannel {
            commitments,
            layer_proofs,
            layer_queries,
            remainder,
            partitioned,
            _hasher: PhantomData,
        })
    }
}

impl<E: FieldElement, H: Hasher> VerifierChannel<E> for DefaultVerifierChannel<E, H> {
    fn fri_layer_proofs(&self) -> &[BatchMerkleProof] {
        &self.layer_proofs
    }

    fn fri_layer_queries(&self) -> &[Vec<E>] {
        &self.layer_queries
    }

    fn fri_remainder(&self) -> &[E] {
        &self.remainder
    }

    fn fri_partitioned(&self) -> bool {
        self.partitioned
    }
}

impl<E: FieldElement, H: Hasher> PublicCoin for DefaultVerifierChannel<E, H> {
    type Hasher = H;

    fn fri_layer_commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }
}
