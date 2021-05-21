// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{
    proof::{Commitments, Context, OodFrame, Queries, StarkProof},
    ConstraintCompositionCoefficients, DeepCompositionCoefficients,
    EvaluationFrame, Air,
};
use crypto::{Hasher, PublicCoin};
use fri::{self, FriProof};
use math::field::{FieldElement};
use std::{marker::PhantomData};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// TYPES AND INTERFACES
// ================================================================================================

pub struct ProverChannel<'a, A: Air, E: FieldElement + From<A::BaseElement>, H: Hasher> {
    air: &'a A,
    coin: PublicCoin<A::BaseElement, H>,
    context: Context,
    trace_root: Option<H::Digest>,
    constraint_root: Option<H::Digest>,
    fri_roots: Vec<H::Digest>,
    pow_nonce: u64,
    _field_element: PhantomData<E>,
}

// PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<'a, A: Air, E: FieldElement + From<A::BaseElement>, H: Hasher> ProverChannel<'a, A, E, H> {
    /// Creates a new prover channel for the specified proof `context`.
    pub fn new(air: &'a A) -> Self {
        let context = Context::new::<A::BaseElement>(air.lde_domain_size(), air.options().clone());

        let mut coin_seed = Vec::new();
        context.write_into(&mut coin_seed);

        ProverChannel {
            air,
            coin: PublicCoin::new(&coin_seed),
            context,
            trace_root: None,
            constraint_root: None,
            fri_roots: Vec::new(),
            pow_nonce: 0,
            _field_element: PhantomData,
        }
    }

    /// Commits the prover the extended execution trace.
    pub fn commit_trace(&mut self, trace_root: H::Digest) {
        assert!(
            self.trace_root.is_none(),
            "trace root has already been committed"
        );
        self.trace_root = Some(trace_root);
        self.coin.reseed(trace_root);
    }

    /// Commits the prover the the constraint evaluations.
    pub fn commit_constraints(&mut self, constraint_root: H::Digest) {
        assert!(
            self.constraint_root.is_none(),
            "constraint root has already been committed"
        );
        self.constraint_root = Some(constraint_root);
        self.coin.reseed(constraint_root);
    }

    pub fn get_constraint_composition_coeffs(&mut self) -> ConstraintCompositionCoefficients<E> {
        self.air.get_constraint_composition_coeffs(&mut self.coin)
    }

    pub fn get_ood_point(&mut self) -> E {
        self.coin.draw()
    }

    pub fn get_deep_composition_coeffs(&mut self) -> DeepCompositionCoefficients<E> {
        self.air.get_deep_composition_coeffs(&mut self.coin)
    }

    pub fn get_query_positions(&mut self) -> Vec<usize> {
        let num_queries = self.context.options().num_queries();
        self.coin
            .draw_integers(num_queries, self.context.lde_domain_size())
    }

    /// Computes query seed from a combination of FRI layers and applies PoW to the seed
    /// based on the grinding_factor specified by the options
    pub fn grind_query_seed(&mut self) {

        let grinding_factor = self.context.options().grinding_factor();

        #[cfg(not(feature = "concurrent"))]
        let nonce = (1..u64::MAX)
            .find(|&nonce| {
                self.coin.check_leading_zeros(nonce) >= grinding_factor
            })
            .expect("nonce not found");
    
        #[cfg(feature = "concurrent")]
        let nonce = (1..u64::MAX)
            .into_par_iter()
            .find_any(|&nonce| {
                self.coin.check_leading_zeros(nonce) >= grinding_factor
            })
            .expect("nonce not found");

        self.pow_nonce = nonce;
        self.coin.reseed_with_int(nonce);
    }

    /// Builds a proof from the previously committed values as well as values passed into
    /// this method.
    pub fn build_proof(
        self,
        trace_queries: Queries,
        constraint_queries: Queries,
        ood_frame: EvaluationFrame<E>,
        ood_evaluations: Vec<E>,
        fri_proof: FriProof,
    ) -> StarkProof {
        let commitments = Commitments::new::<H>(
            self.trace_root.unwrap(),
            self.constraint_root.unwrap(),
            self.fri_roots,
        );

        StarkProof {
            context: self.context,
            commitments,
            trace_queries,
            constraint_queries,
            ood_frame: OodFrame::new(ood_frame, ood_evaluations),
            fri_proof,
            pow_nonce: self.pow_nonce,
        }
    }
}

impl<'a, A: Air, E: FieldElement + From<A::BaseElement>, H: Hasher> fri::ProverChannel<E>
    for ProverChannel<'a, A, E, H>
{
    type Hasher = H;

    /// Commits the prover to the a FRI layer.
    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.fri_roots.push(layer_root);
        self.coin.reseed(layer_root);
    }

    fn draw_fri_alpha(&mut self) -> E {
        self.coin.draw()
    }
}
