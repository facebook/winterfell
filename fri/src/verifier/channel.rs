// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{folding::quartic, FriProof, PublicCoin, VerifierError};
use crypto::{BatchMerkleProof, DefaultRandomElementGenerator, Hasher, MerkleTree};
use math::{field::FieldElement, utils::read_elements_into_vec};
use std::{convert::TryInto, marker::PhantomData};

type Bytes = Vec<u8>;

// VERIFIER CHANNEL TRAIT
// ================================================================================================

pub trait VerifierChannel<E: FieldElement>: PublicCoin {
    type Hasher: Hasher;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    fn fri_layer_proofs(&self) -> &[BatchMerkleProof];
    fn fri_layer_queries(&self) -> &[Vec<Bytes>];
    fn fri_remainder(&self) -> &[u8];
    fn fri_partitioned(&self) -> bool;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns FRI query values at the specified positions from the FRI layer at the
    /// specified index. This also checks if the values are valid against the FRI layer
    /// commitment sent by the prover.
    fn read_layer_queries(
        &self,
        layer_idx: usize,
        positions: &[usize],
    ) -> Result<Vec<[E; 4]>, VerifierError> {
        let hash_fn = Self::Hasher::hash_fn();
        let layer_root = self.fri_layer_commitments()[layer_idx];
        let layer_proof = &self.fri_layer_proofs()[layer_idx];
        if !MerkleTree::verify_batch(&layer_root, &positions, &layer_proof, hash_fn) {
            return Err(VerifierError::LayerCommitmentMismatch(layer_idx));
        }

        // convert query bytes into field elements of appropriate type
        let mut queries = Vec::new();
        for query_bytes in self.fri_layer_queries()[layer_idx].iter() {
            let query: [E; 4] = read_elements_into_vec(query_bytes)
                .map_err(|err| {
                    VerifierError::LayerDeserializationError(layer_idx, err.to_string())
                })?
                .try_into()
                .map_err(|_| {
                    VerifierError::LayerDeserializationError(
                        layer_idx,
                        "failed to convert vec of elements to array of 4 element".to_string(),
                    )
                })?;
            queries.push(query);
        }

        Ok(queries)
    }

    /// Reads FRI remainder values (last FRI layer). This also checks that the remainder is
    /// valid against the commitment sent by the prover.
    fn read_remainder(&self) -> Result<Vec<E>, VerifierError> {
        let hash_fn = Self::Hasher::hash_fn();
        // convert remainder bytes into field elements of appropriate type
        let remainder = read_elements_into_vec(&self.fri_remainder())
            .map_err(|err| VerifierError::RemainderDeserializationError(err.to_string()))?;

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

    /// Decomposes FRI proof struct into batch Merkle proofs and query values for each
    /// FRI layer, as well as remainder (the last FRI layer).
    fn parse_fri_proof(proof: FriProof) -> (Vec<BatchMerkleProof>, Vec<Vec<Vec<u8>>>, Vec<u8>) {
        let hash_fn = Self::Hasher::hash_fn();
        let mut fri_queries = Vec::with_capacity(proof.layers.len());
        let mut fri_proofs = Vec::with_capacity(proof.layers.len());
        for layer in proof.layers.into_iter() {
            let mut hashed_values = Vec::new();
            for value_bytes in layer.values.iter() {
                let mut buf = [0u8; 32];
                hash_fn(value_bytes, &mut buf);
                hashed_values.push(buf);
            }

            fri_proofs.push(BatchMerkleProof {
                values: hashed_values,
                nodes: layer.paths.clone(),
                depth: layer.depth,
            });
            fri_queries.push(layer.values);
        }

        (fri_proofs, fri_queries, proof.rem_values)
    }

    fn num_fri_partitions(&self) -> usize {
        if self.fri_partitioned() {
            self.fri_remainder().len() / E::ELEMENT_BYTES
        } else {
            1
        }
    }
}

// DEFAULT VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

pub struct DefaultVerifierChannel<E: FieldElement, H: Hasher> {
    commitments: Vec<[u8; 32]>,
    proofs: Vec<BatchMerkleProof>,
    queries: Vec<Vec<Bytes>>,
    remainder: Bytes,
    partitioned: bool,
    _element: PhantomData<E>,
    _hasher: PhantomData<H>,
}

impl<E: FieldElement, H: Hasher> DefaultVerifierChannel<E, H> {
    /// Builds a new verifier channel from the specified parameters.
    pub fn new(proof: FriProof, commitments: Vec<[u8; 32]>) -> Self {
        let partitioned = proof.partitioned;
        let (proofs, queries, remainder) = Self::parse_fri_proof(proof);

        DefaultVerifierChannel {
            commitments,
            proofs,
            queries,
            remainder,
            partitioned,
            _element: PhantomData,
            _hasher: PhantomData,
        }
    }
}

impl<E: FieldElement, H: Hasher> VerifierChannel<E> for DefaultVerifierChannel<E, H> {
    type Hasher = H;

    fn fri_layer_proofs(&self) -> &[BatchMerkleProof] {
        &self.proofs
    }

    fn fri_layer_queries(&self) -> &[Vec<Bytes>] {
        &self.queries
    }

    fn fri_remainder(&self) -> &[u8] {
        &self.remainder
    }

    fn fri_partitioned(&self) -> bool {
        self.partitioned
    }
}

impl<E: FieldElement, H: Hasher> PublicCoin for DefaultVerifierChannel<E, H> {
    type RandomElementGenerator = DefaultRandomElementGenerator<H>;

    fn fri_layer_commitments(&self) -> &[[u8; 32]] {
        &self.commitments
    }
}
