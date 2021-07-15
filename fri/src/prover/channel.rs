// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{Hasher, PublicCoin};
use math::{FieldElement, StarkField};
use std::marker::PhantomData;

// PROVER CHANNEL TRAIT
// ================================================================================================

/// Defines an interface for a channel over which a prover communicates with a verifier.
///
/// The prover uses this channel
pub trait ProverChannel<E: FieldElement> {
    /// Hash function used by the prover to commit to polynomial evaluations.
    type Hasher: Hasher;

    /// Sends a layer commitment to the verifier.
    ///
    /// A layer commitment is a root of a Merkle tree built from evaluations of a polynomial at
    /// a given layer.
    fn commit_fri_layer(
        &mut self,
        layer_root: <<Self as ProverChannel<E>>::Hasher as Hasher>::Digest,
    );

    /// Returns a random α drawn uniformly at random from the entire field.
    ///
    /// The prover uses this α to build the next FRI layer.
    ///
    /// While in the interactive version of the protocol the verifier send a random α to the
    /// prover, in the non-interactive version, the α is pseudo-randomly generated based on the
    /// values the prover previously wrote into the channel.
    fn draw_fri_alpha(&mut self) -> E;
}

// DEFAULT PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

/// Provides a default implementation of the [ProverChannel] trait.
///
/// Though this implementation is intended primarily for testing purposes, it can be used in
/// production use cases as well.
pub struct DefaultProverChannel<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    coin: PublicCoin<B, H>,
    commitments: Vec<H::Digest>,
    domain_size: usize,
    num_queries: usize,
    _field_element: PhantomData<E>,
}

impl<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> DefaultProverChannel<B, E, H> {
    /// Returns a new prover channel instantiated from the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// * `domain_size` is smaller than 8 or is not a power of two.
    /// * `num_queries` is zero.
    pub fn new(domain_size: usize, num_queries: usize) -> Self {
        assert!(
            domain_size >= 8,
            "domain size must be at least 8, but was {}",
            domain_size
        );
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two, but was {}",
            domain_size
        );
        assert!(
            num_queries > 0,
            "number of queries must be greater than zero"
        );
        DefaultProverChannel {
            coin: PublicCoin::new(&[]),
            commitments: Vec::new(),
            domain_size,
            num_queries,
            _field_element: PhantomData,
        }
    }

    /// Draws a set of positions for the domain specified by
    ///
    /// In the interactive version of the protocol, the verifier draws these positions
    /// uniformly at random in the beginning of the query phase and sends them to the prover.
    /// In the non-interactive version, the positions are pseudo-randomly generated based on
    /// the values the prover has written into this channel.
    ///
    /// # Panics if:
    ///
    pub fn draw_query_positions(&mut self) -> Vec<usize> {
        self.coin
            .draw_integers(self.num_queries, self.domain_size)
            .expect("failed to draw query position")
    }

    /// Returns a list of FRI layer commitments written by the prover into this channel.
    pub fn layer_commitments(&self) -> &[H::Digest] {
        &self.commitments
    }
}

impl<B, E, H> ProverChannel<E> for DefaultProverChannel<B, E, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: Hasher,
{
    type Hasher = H;

    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.commitments.push(layer_root);
        self.coin.reseed(layer_root);
    }

    fn draw_fri_alpha(&mut self) -> E {
        self.coin.draw().expect("failed to draw FRI alpha")
    }
}
