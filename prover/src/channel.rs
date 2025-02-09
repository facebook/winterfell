// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::marker::PhantomData;

use air::{
    proof::{Commitments, Context, OodFrame, Proof, Queries, TraceOodFrame},
    Air, ConstraintCompositionCoefficients, DeepCompositionCoefficients,
};
use crypto::{ElementHasher, RandomCoin, VectorCommitment};
use fri::FriProof;
use math::{FieldElement, ToElements};
#[cfg(feature = "concurrent")]
use utils::iterators::*;

// TYPES AND INTERFACES
// ================================================================================================

pub struct ProverChannel<'a, A, E, H, R, V>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseField>,
    H: ElementHasher<BaseField = A::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    air: &'a A,
    public_coin: R,
    context: Context,
    commitments: Commitments,
    ood_frame: OodFrame,
    pow_nonce: u64,
    _field_element: PhantomData<E>,
    _vector_commitment: PhantomData<V>,
}

// PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<'a, A, E, H, R, V> ProverChannel<'a, A, E, H, R, V>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseField>,
    H: ElementHasher<BaseField = A::BaseField>,
    R: RandomCoin<BaseField = A::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new prover channel for the specified `air` and public inputs.
    pub fn new(air: &'a A, mut pub_inputs_elements: Vec<A::BaseField>) -> Self {
        let num_constraints =
            air.context().num_assertions() + air.context().num_transition_constraints();
        let context = Context::new::<A::BaseField>(
            air.trace_info().clone(),
            air.options().clone(),
            num_constraints,
        );

        // build a seed for the public coin; the initial seed is a hash of the proof context and
        // the public inputs, but as the protocol progresses, the coin will be reseeded with the
        // info sent to the verifier
        let mut coin_seed_elements = context.to_elements();
        coin_seed_elements.append(&mut pub_inputs_elements);

        ProverChannel {
            air,
            public_coin: RandomCoin::new(&coin_seed_elements),
            context,
            commitments: Commitments::default(),
            ood_frame: OodFrame::default(),
            pow_nonce: 0,
            _field_element: PhantomData,
            _vector_commitment: PhantomData,
        }
    }

    // COMMITMENT METHODS
    // --------------------------------------------------------------------------------------------

    /// Commits the prover the extended execution trace.
    pub fn commit_trace(&mut self, trace_root: H::Digest) {
        self.commitments.add::<H>(&trace_root);
        self.public_coin.reseed(trace_root);
    }

    /// Commits the prover to the evaluations of the constraint composition polynomial.
    pub fn commit_constraints(&mut self, constraint_root: H::Digest) {
        self.commitments.add::<H>(&constraint_root);
        self.public_coin.reseed(constraint_root);
    }

    /// Saves the evaluations of trace polynomials over the out-of-domain evaluation frame. This
    /// also reseeds the public coin with the hashes of the evaluation frame states.
    pub fn send_ood_trace_states(&mut self, trace_ood_frame: &TraceOodFrame<E>) {
        let trace_states_hash = self.ood_frame.set_trace_states::<E, H>(trace_ood_frame);
        self.public_coin.reseed(trace_states_hash);
    }

    /// Saves the evaluations of constraint composition polynomial columns at the out-of-domain
    /// point. This also reseeds the public coin wit the hash of the evaluations.
    pub fn send_ood_constraint_evaluations(&mut self, evaluations: &[E]) {
        self.ood_frame.set_constraint_evaluations(evaluations);
        self.public_coin.reseed(H::hash_elements(evaluations));
    }

    // PUBLIC COIN METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the inner public coin
    pub fn public_coin(&mut self) -> &mut R {
        &mut self.public_coin
    }

    /// Returns a set of coefficients for constructing a constraint composition polynomial.
    ///
    /// The coefficients are drawn from the public coin uniformly at random.
    pub fn get_constraint_composition_coeffs(&mut self) -> ConstraintCompositionCoefficients<E> {
        self.air
            .get_constraint_composition_coefficients(&mut self.public_coin)
            .expect("failed to draw composition coefficients")
    }

    /// Returns an out-of-domain point drawn uniformly at random from the public coin.
    pub fn get_ood_point(&mut self) -> E {
        self.public_coin.draw().expect("failed to draw OOD point")
    }

    /// Returns a set of coefficients for constructing a DEEP composition polynomial.
    ///
    /// The coefficients are drawn from the public coin uniformly at random.
    pub fn get_deep_composition_coeffs(&mut self) -> DeepCompositionCoefficients<E> {
        self.air
            .get_deep_composition_coefficients(&mut self.public_coin)
            .expect("failed to draw DEEP composition coefficients")
    }

    /// Returns a set of positions in the LDE domain against which the evaluations of trace and
    /// constraint composition polynomials should be queried.
    ///
    /// The positions are drawn from the public coin uniformly at random. Duplicate positions
    /// are removed from the returned vector.
    pub fn get_query_positions(&mut self) -> Vec<usize> {
        let num_queries = self.context.options().num_queries();
        let lde_domain_size = self.context.lde_domain_size();
        let mut positions = self
            .public_coin
            .draw_integers(num_queries, lde_domain_size, self.pow_nonce)
            .expect("failed to draw query position");

        // remove any duplicate positions from the list
        positions.sort_unstable();
        positions.dedup();

        positions
    }

    /// Determines a nonce, which when hashed with the current seed of the public coin results
    /// in a new seed with the number of leading zeros equal to the grinding_factor specified
    /// in the proof options.
    pub fn grind_query_seed(&mut self) {
        let grinding_factor = self.context.options().grinding_factor();

        #[cfg(not(feature = "concurrent"))]
        let nonce = (1..u64::MAX)
            .find(|&nonce| self.public_coin.check_leading_zeros(nonce) >= grinding_factor)
            .expect("nonce not found");

        #[cfg(feature = "concurrent")]
        let nonce = (1..u64::MAX)
            .into_par_iter()
            .find_any(|&nonce| self.public_coin.check_leading_zeros(nonce) >= grinding_factor)
            .expect("nonce not found");

        self.pow_nonce = nonce;
    }

    // PROOF BUILDER
    // --------------------------------------------------------------------------------------------
    /// Builds a proof from the previously committed values as well as values passed into
    /// this method.
    pub fn build_proof(
        self,
        trace_queries: Vec<Queries>,
        constraint_queries: Queries,
        fri_proof: FriProof,
        num_query_positions: usize,
    ) -> Proof {
        assert!(num_query_positions <= u8::MAX as usize, "num_query_positions too big");

        Proof {
            context: self.context,
            commitments: self.commitments,
            ood_frame: self.ood_frame,
            trace_queries,
            constraint_queries,
            fri_proof,
            pow_nonce: self.pow_nonce,
            num_unique_queries: num_query_positions as u8,
        }
    }
}

// FRI PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<A, E, H, R, V> fri::ProverChannel<E> for ProverChannel<'_, A, E, H, R, V>
where
    A: Air,
    E: FieldElement<BaseField = A::BaseField>,
    H: ElementHasher<BaseField = A::BaseField>,
    R: RandomCoin<BaseField = A::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    type Hasher = H;

    /// Commits the prover to a FRI layer.
    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.commitments.add::<H>(&layer_root);
        self.public_coin.reseed(layer_root);
    }

    /// Returns a new alpha drawn from the public coin.
    fn draw_fri_alpha(&mut self) -> E {
        self.public_coin.draw().expect("failed to draw FRI alpha")
    }
}
