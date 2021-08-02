// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{utils::hash_values, FriProof, VerifierError};
use crypto::{BatchMerkleProof, ElementHasher, Hasher, MerkleTree};
use math::FieldElement;
use utils::{collections::Vec, group_vector_elements, transpose_slice, DeserializationError};

// VERIFIER CHANNEL TRAIT
// ================================================================================================

/// Defines an interface for a channel over which a verifier communicates with a prover.
///
/// This trait abstracts away implementation specifics of the [FriProof] struct. Thus, instead of
/// dealing with FRI proofs directly, the verifier can read the data as if it was sent by the
/// prover via an interactive channel.
///
/// Note: that reading removes the data from the channel. Thus, reading duplicated values from
/// the channel should not be possible.
pub trait VerifierChannel<E: FieldElement> {
    /// Hash function used by the prover to commit to polynomial evaluations.
    type Hasher: ElementHasher<BaseField = E::BaseField>;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of partitions used during proof generation.
    fn read_fri_num_partitions(&self) -> usize;

    /// Reads and removes from the channel all FRI layer commitments sent by the prover.
    ///
    /// In the interactive version of the protocol, the prover sends layer commitments to the
    /// verifier one-by-one, and the verifier responds with a value α drawn uniformly at random
    /// from the entire field after each layer commitment is received. In the non-interactive
    /// version, the verifier can read all layer commitments at once, and then generate α values
    /// locally.
    fn read_fri_layer_commitments(
        &mut self,
    ) -> Vec<<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest>;

    /// Reads and removes from the channel evaluations of the polynomial at the queried positions
    /// for the next FRI layer.
    ///
    /// In the interactive version of the protocol, these evaluations are sent from the prover to
    /// the verifier during the query phase of the FRI protocol.
    ///
    /// It is expected that layer queries and layer proofs at the same FRI layer are consistent.
    /// That is, query values hash into the leaf nodes of corresponding Merkle authentication
    /// paths.
    fn take_next_fri_layer_queries(&mut self) -> Vec<E>;

    /// Reads and removes from the channel Merkle authentication paths for queried evaluations for
    /// the next FRI layer.
    ///
    /// In the interactive version of the protocol, these authentication paths are sent from the
    /// prover to the verifier during the query phase of the FRI protocol.
    ///
    /// It is expected that layer proofs and layer queries at the same FRI layer are consistent.
    /// That is, query values hash into the leaf nodes of corresponding Merkle authentication
    /// paths.
    fn take_next_fri_layer_proof(&mut self) -> BatchMerkleProof<Self::Hasher>;

    /// Reads and removes the remainder (last FRI layer) values from the channel.
    fn take_fri_remainder(&mut self) -> Vec<E>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns FRI query values at the specified positions from the current FRI layer and advances
    /// layer pointer by one.
    ///
    /// This also checks if the values are valid against the provided FRI layer commitment.
    ///
    /// # Errors
    /// Returns an error if query values did not match layer commitment.
    fn read_layer_queries<const N: usize>(
        &mut self,
        positions: &[usize],
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<[E; N]>, VerifierError> {
        let layer_proof = self.take_next_fri_layer_proof();
        MerkleTree::<Self::Hasher>::verify_batch(commitment, positions, &layer_proof)
            .map_err(|_| VerifierError::LayerCommitmentMismatch)?;

        // TODO: make sure layer queries hash into leaves of layer proof

        let layer_queries = self.take_next_fri_layer_queries();
        Ok(group_vector_elements(layer_queries))
    }

    /// Returns FRI remainder values (last FRI layer) read from this channel.
    ///
    /// This also checks whether the remainder is valid against the provided commitment.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Remainder values read from the channel cannot be used to construct a fully-balanced
    ///   Merkle tree.
    /// - If the root of the Merkle tree constructed from the remainder values does not match
    ///   the specified `commitment`.
    fn read_remainder<const N: usize>(
        &mut self,
        commitment: &<<Self as VerifierChannel<E>>::Hasher as Hasher>::Digest,
    ) -> Result<Vec<E>, VerifierError> {
        let remainder = self.take_fri_remainder();

        // build remainder Merkle tree
        let remainder_values = transpose_slice(&remainder);
        let hashed_values = hash_values::<Self::Hasher, E, N>(&remainder_values);
        let remainder_tree = MerkleTree::<Self::Hasher>::new(hashed_values)
            .map_err(|err| VerifierError::RemainderTreeConstructionFailed(format!("{}", err)))?;

        // make sure the root of the tree matches the committed root of the last layer
        if commitment != remainder_tree.root() {
            return Err(VerifierError::RemainderCommitmentMismatch);
        }

        Ok(remainder)
    }
}

// DEFAULT VERIFIER CHANNEL IMPLEMENTATION
// ================================================================================================

/// Provides a default implementation of the [VerifierChannel] trait.
///
/// Default verifier channel can be instantiated directly from a [FriProof] struct.
///
/// Though this implementation is primarily intended for testing purposes, it can be used in
/// production use cases as well.
pub struct DefaultVerifierChannel<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    layer_commitments: Vec<H::Digest>,
    layer_proofs: Vec<BatchMerkleProof<H>>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    num_partitions: usize,
}

impl<E, H> DefaultVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    /// Builds a new verifier channel from the specified [FriProof].
    ///
    /// # Errors
    /// Returns an error if the specified `proof` could not be parsed correctly.
    pub fn new(
        proof: FriProof,
        layer_commitments: Vec<H::Digest>,
        domain_size: usize,
        folding_factor: usize,
    ) -> Result<Self, DeserializationError> {
        let num_partitions = proof.num_partitions();

        let remainder = proof.parse_remainder()?;
        let (layer_queries, layer_proofs) =
            proof.parse_layers::<H, E>(domain_size, folding_factor)?;

        Ok(DefaultVerifierChannel {
            layer_commitments,
            layer_proofs,
            layer_queries,
            remainder,
            num_partitions,
        })
    }
}

impl<E, H> VerifierChannel<E> for DefaultVerifierChannel<E, H>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    type Hasher = H;

    fn read_fri_num_partitions(&self) -> usize {
        self.num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<H::Digest> {
        self.layer_commitments.drain(..).collect()
    }

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
