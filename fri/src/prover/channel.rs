// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crypto::{ElementHasher, Hasher, RandomCoin};
use math::FieldElement;
use rand::{distributions::Standard, prelude::Distribution, Rng, RngCore, SeedableRng};

// PROVER CHANNEL TRAIT
// ================================================================================================

/// Defines an interface for a channel over which a prover communicates with a verifier.
///
/// The prover uses this channel to send commitments to FRI layer polynomials to the verifier, and
/// then to draw a random value α from the channel after each commitment is sent. The prover then
/// uses this α to construct the next FRI layer.
///
/// In the interactive version of the protocol, the verifier chooses α uniformly at random from
/// the entire field. In the non-interactive version, the α is drawn pseudo-randomly based on the
/// commitments the prover has written into the channel up to this point.
pub trait ProverChannel<E: FieldElement> {
    /// Hash function used by the prover to commit to polynomial evaluations.
    type Hasher: ElementHasher<BaseField = E::BaseField>;

    /// Sends a layer commitment to the verifier.
    ///
    /// A layer commitment is the commitment string of a vector commitment to the vector of
    /// evaluations of a polynomial at a given layer. The vector commitment is built by
    /// first transposing evaluations into a two-dimensional matrix where each row contains
    /// values needed to compute a single value of the next FRI layer, and then computing
    /// the hash of each row to get one entry of the vector being committed to. Thus, the number
    /// of elements grouped into a single leaf is equal to the `folding_factor` used for FRI layer
    /// construction.
    fn commit_fri_layer(
        &mut self,
        layer_root: <Self::Hasher as Hasher>::Digest,
    ) -> Option<<Self::Hasher as Hasher>::Digest>;

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
pub struct DefaultProverChannel<E, H, P, R>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    P: RngCore,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
{
    public_coin: R,
    commitments: Vec<H::Digest>,
    domain_size: usize,
    num_queries: usize,
    is_zk: bool,
    salts: Vec<Option<H::Digest>>,
    prng: Option<P>,
    _field_element: PhantomData<E>,
}

impl<E, H, P, R> DefaultProverChannel<E, H, P, R>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    P: RngCore + SeedableRng,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
{
    /// Returns a new prover channel instantiated from the specified parameters.
    ///
    /// # Panics
    /// Panics if:
    /// * `domain_size` is smaller than 8 or is not a power of two.
    /// * `num_queries` is zero.
    pub fn new(
        domain_size: usize,
        num_queries: usize,
        is_zk: bool,
        seed: Option<<P as SeedableRng>::Seed>,
    ) -> Self {
        assert!(domain_size >= 8, "domain size must be at least 8, but was {domain_size}");
        assert!(
            domain_size.is_power_of_two(),
            "domain size must be a power of two, but was {domain_size}"
        );
        assert!(num_queries > 0, "number of queries must be greater than zero");

        let prng = if is_zk {
            Some(P::from_seed(seed.expect("must provide the seed when zk is enabled")))
        } else {
            None
        };
        DefaultProverChannel {
            public_coin: RandomCoin::new(&[]),
            commitments: Vec::new(),
            domain_size,
            num_queries,
            is_zk,
            salts: vec![],
            prng,
            _field_element: PhantomData,
        }
    }

    /// Draws a set of positions at which the polynomial evaluations committed at the first FRI
    /// layer should be queried.
    ///
    /// The positions are pseudo-randomly generated based on the values the prover has written
    /// into this channel and a PoW nonce.
    ///
    /// # Panics
    /// Panics if the specified number of unique positions could not be drawn from the specified
    /// domain. Both number of queried positions and domain size are specified during
    /// construction of the channel.
    pub fn draw_query_positions(&mut self, nonce: u64) -> Vec<usize> {
        self.public_coin
            .draw_integers(self.num_queries, self.domain_size, nonce)
            .expect("failed to draw query position")
    }

    /// Returns a list of FRI layer commitments written by the prover into this channel.
    pub fn layer_commitments(&self) -> &[H::Digest] {
        &self.commitments
    }
}

impl<E, H, P, R> ProverChannel<E> for DefaultProverChannel<E, H, P, R>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    P: RngCore,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    Standard: Distribution<<H as Hasher>::Digest>,
{
    type Hasher = H;

    fn commit_fri_layer(
        &mut self,
        layer_root: H::Digest,
    ) -> Option<<Self::Hasher as Hasher>::Digest> {
        self.commitments.push(layer_root);

        // sample a salt for Fiat-Shamir if zero-knowledge is enabled
        let salt = if self.is_zk {
            let digest = self
                .prng
                .as_mut()
                .expect("should have a PRNG when zk is enabled")
                .sample(Standard);
            Some(digest)
        } else {
            None
        };
        self.salts.push(salt);
        self.public_coin.reseed_with_salt(layer_root, salt);
        salt
    }

    fn draw_fri_alpha(&mut self) -> E {
        self.public_coin.draw().expect("failed to draw FRI alpha")
    }
}
