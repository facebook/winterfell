// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{utils::hash_values, FriProof, ProofSerializationError, VerifierError};
use crypto::{BatchMerkleProof, Hasher, MerkleTree};
use math::field::FieldElement;
use utils::{group_vector_elements, transpose_slice};

// VERIFIER CHANNEL TRAIT
// ================================================================================================

pub trait VerifierChannel<E: FieldElement> {
    type Hasher: Hasher;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<Self::Hasher>;
    fn take_next_fri_layer_queries(&mut self) -> Vec<E>;
    fn take_fri_remainder(&mut self) -> Vec<E>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns FRI query values at the specified positions from the FRI layer at the
    /// specified index. This also checks if the values are valid against the provided
    /// FRI layer commitment.
    fn read_layer_queries<const N: usize>(
        &mut self,
        layer_idx: usize,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<[E; N]>, VerifierError> {
        let layer_proof = self.take_next_fri_layer_proof();
        if !MerkleTree::<Self::Hasher>::verify_batch(commitment, &positions, &layer_proof) {
            return Err(VerifierError::LayerCommitmentMismatch(layer_idx));
        }

        let layer_queries = self.take_next_fri_layer_queries();
        Ok(group_vector_elements(layer_queries))
    }

    /// Reads FRI remainder values (last FRI layer). This also checks that the remainder is
    /// valid against the provided commitment.
    fn read_remainder<const N: usize>(
        &mut self,
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<E>, VerifierError> {
        let remainder = self.take_fri_remainder();

        // build remainder Merkle tree
        let remainder_values = transpose_slice(&remainder);
        let hashed_values = hash_values::<Self::Hasher, E, N>(&remainder_values);
        let remainder_tree = MerkleTree::<Self::Hasher>::new(hashed_values);

        // make sure the root of the tree matches the committed root of the last layer
        if commitment != remainder_tree.root() {
            return Err(VerifierError::RemainderCommitmentMismatch);
        }

        Ok(remainder)
    }
}

// DEFAULT VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

pub struct DefaultVerifierChannel<E: FieldElement, H: Hasher> {
    layer_proofs: Vec<BatchMerkleProof<H>>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    num_partitions: usize,
}

impl<E: FieldElement, H: Hasher> DefaultVerifierChannel<E, H> {
    /// Builds a new verifier channel from the specified parameters.
    pub fn new(
        proof: FriProof,
        domain_size: usize,
        folding_factor: usize,
    ) -> Result<Self, ProofSerializationError> {
        let num_partitions = proof.num_partitions();

        let remainder = proof.parse_remainder()?;
        let (layer_queries, layer_proofs) =
            proof.parse_layers::<H, E>(domain_size, folding_factor)?;

        Ok(DefaultVerifierChannel {
            layer_proofs,
            layer_queries,
            remainder,
            num_partitions,
        })
    }

    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }
}

impl<E: FieldElement, H: Hasher> VerifierChannel<E> for DefaultVerifierChannel<E, H> {
    type Hasher = H;

    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<H> {
        self.layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<E> {
        self.layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<E> {
        self.remainder.clone()
    }
}
