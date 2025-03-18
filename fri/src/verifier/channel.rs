// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crypto::{ElementHasher, Hasher, VectorCommitment};
use math::FieldElement;
use utils::{group_slice_elements, DeserializationError};

use crate::{FriProof, VerifierError};

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
    /// Vector commitment used to commit to polynomial evaluations.
    type VectorCommitment: VectorCommitment<Self::Hasher>;

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
    fn read_fri_layer_commitments(&mut self) -> Vec<<Self::Hasher as Hasher>::Digest>;

    /// Reads and removes from the channel evaluations of the polynomial at the queried positions
    /// for the next FRI layer.
    ///
    /// In the interactive version of the protocol, these evaluations are sent from the prover to
    /// the verifier during the query phase of the FRI protocol.
    ///
    /// It is expected that layer queries and layer proofs at the same FRI layer are consistent.
    /// That is, query values hash into the leaf nodes of corresponding vector commitment.
    fn take_next_fri_layer_queries(&mut self) -> Vec<E>;

    /// Reads and removes from the channel vector commitment opening proofs of queried evaluations
    /// for the next FRI layer.
    ///
    /// In the interactive version of the protocol, these authentication paths are sent from the
    /// prover to the verifier during the query phase of the FRI protocol.
    ///
    /// It is expected that layer proofs and layer queries at the same FRI layer are consistent.
    /// That is, query values hash into the elements of the vector committed to using the specified
    /// vector commitment scheme.
    fn take_next_fri_layer_proof(
        &mut self,
    ) -> <Self::VectorCommitment as VectorCommitment<Self::Hasher>>::MultiProof;

    /// Reads and removes the remainder polynomial from the channel.
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
        commitment: &<Self::Hasher as Hasher>::Digest,
    ) -> Result<Vec<[E; N]>, VerifierError> {
        let layer_proof = self.take_next_fri_layer_proof();
        let layer_queries = self.take_next_fri_layer_queries();
        // build the values (i.e., polynomial evaluations over a coset of a multiplicative subgroup
        // of the current evaluation domain) corresponding to each leaf of the layer commitment
        let leaf_values = group_slice_elements(&layer_queries);
        // hash the aforementioned values to get the leaves to be verified against the previously
        // received commitment
        let hashed_values: Vec<<Self::Hasher as Hasher>::Digest> = leaf_values
            .iter()
            .map(|seg| <Self::Hasher as ElementHasher>::hash_elements(seg))
            .collect();

        <<Self as VerifierChannel<E>>::VectorCommitment as VectorCommitment<Self::Hasher>>::verify_many(
            *commitment,
            positions,
            &hashed_values,
            &layer_proof,
        )
        .map_err(|_| VerifierError::LayerCommitmentMismatch)?;

        Ok(leaf_values.to_vec())
    }

    /// Returns FRI remainder polynomial read from this channel.
    fn read_remainder(&mut self) -> Result<Vec<E>, VerifierError> {
        let remainder = self.take_fri_remainder();

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
pub struct DefaultVerifierChannel<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
> {
    layer_commitments: Vec<H::Digest>,
    layer_proofs: Vec<V::MultiProof>,
    layer_queries: Vec<Vec<E>>,
    remainder: Vec<E>,
    num_partitions: usize,
    _h: PhantomData<H>,
}

impl<E, H, V> DefaultVerifierChannel<E, H, V>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
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
            proof.parse_layers::<E, H, V>(domain_size, folding_factor)?;

        Ok(DefaultVerifierChannel {
            layer_commitments,
            layer_proofs,
            layer_queries,
            remainder,
            num_partitions,
            _h: PhantomData,
        })
    }
}

impl<E, H, V> VerifierChannel<E> for DefaultVerifierChannel<E, H, V>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    type Hasher = H;
    type VectorCommitment = V;

    fn read_fri_num_partitions(&self) -> usize {
        self.num_partitions
    }

    fn read_fri_layer_commitments(&mut self) -> Vec<H::Digest> {
        self.layer_commitments.drain(..).collect()
    }

    fn take_next_fri_layer_proof(&mut self) -> V::MultiProof {
        self.layer_proofs.remove(0)
    }

    fn take_next_fri_layer_queries(&mut self) -> Vec<E> {
        self.layer_queries.remove(0)
    }

    fn take_fri_remainder(&mut self) -> Vec<E> {
        self.remainder.clone()
    }
}
