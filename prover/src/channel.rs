// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{
    proof::{Commitments, Context, OodFrame, Queries, StarkProof},
    ComputationContext, EvaluationFrame, PublicCoin,
};
use crypto::Hasher;
use fri::{self, FriProof};
use math::{
    field::{FieldElement, StarkField},
    utils::log2,
};
use std::convert::TryInto;

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// TYPES AND INTERFACES
// ================================================================================================

pub struct ProverChannel<H: Hasher> {
    context: ComputationContext,
    trace_root: Option<H::Digest>,
    constraint_root: Option<H::Digest>,
    fri_roots: Vec<H::Digest>,
    query_seed: Option<H::Digest>,
    pow_nonce: u64,
}

// PROVER CHANNEL IMPLEMENTATION
// ================================================================================================

impl<H: Hasher> ProverChannel<H> {
    /// Creates a new prover channel for the specified proof `context`.
    pub fn new(context: &ComputationContext) -> Self {
        ProverChannel {
            context: context.clone(),
            trace_root: None,
            constraint_root: None,
            fri_roots: Vec::new(),
            query_seed: None,
            pow_nonce: 0,
        }
    }

    /// Commits the prover the extended execution trace.
    pub fn commit_trace(&mut self, trace_root: H::Digest) {
        assert!(
            self.trace_root.is_none(),
            "trace root has already been committed"
        );
        self.trace_root = Some(trace_root);
    }

    /// Commits the prover the the constraint evaluations.
    pub fn commit_constraints(&mut self, constraint_root: H::Digest) {
        assert!(
            self.constraint_root.is_none(),
            "constraint root has already been committed"
        );
        self.constraint_root = Some(constraint_root);
    }

    /// Computes query seed from a combination of FRI layers and applies PoW to the seed
    /// based on the grinding_factor specified by the options
    pub fn grind_query_seed(&mut self) {
        assert!(
            !self.fri_roots.is_empty(),
            "FRI layers haven't been computed yet"
        );
        assert!(
            self.query_seed.is_none(),
            "query seed has already been computed"
        );
        let options = self.context().options();
        let seed = H::merge_many(&self.fri_roots);
        let (seed, nonce) = find_pow_nonce::<H>(seed, options.grinding_factor());
        self.query_seed = Some(seed);
        self.pow_nonce = nonce;
    }

    /// Builds a proof from the previously committed values as well as values passed into
    /// this method.
    pub fn build_proof<B: StarkField, E: FieldElement + From<B>>(
        self,
        trace_queries: Queries,
        constraint_queries: Queries,
        ood_frame: EvaluationFrame<E>,
        ood_evaluations: Vec<E>,
        fri_proof: FriProof,
    ) -> StarkProof {
        let options = self.context.options().clone();
        let commitments = Commitments::new::<H>(
            self.trace_root.unwrap(),
            self.constraint_root.unwrap(),
            self.fri_roots,
        );

        StarkProof {
            context: Context {
                lde_domain_depth: log2(self.context.lde_domain_size()) as u8,
                field_modulus_bytes: B::get_modulus_le_bytes(),
                options,
            },
            commitments,
            trace_queries,
            constraint_queries,
            ood_frame: OodFrame::new(ood_frame, ood_evaluations),
            fri_proof,
            pow_nonce: self.pow_nonce,
        }
    }
}

impl<H: Hasher> fri::ProverChannel for ProverChannel<H> {
    /// Commits the prover to the a FRI layer.
    fn commit_fri_layer(&mut self, layer_root: H::Digest) {
        self.fri_roots.push(layer_root);
    }
}

// PUBLIC COIN IMPLEMENTATION
// ================================================================================================

impl<H: Hasher> PublicCoin for ProverChannel<H> {
    fn context(&self) -> &ComputationContext {
        &self.context
    }

    fn constraint_seed(&self) -> H::Digest {
        assert!(self.trace_root.is_some(), "constraint seed is not set");
        self.trace_root.unwrap()
    }

    fn composition_seed(&self) -> H::Digest {
        assert!(
            self.constraint_root.is_some(),
            "composition seed is not set"
        );
        self.constraint_root.unwrap()
    }

    fn query_seed(&self) -> H::Digest {
        assert!(self.query_seed.is_some(), "query seed is not set");
        self.query_seed.unwrap()
    }
}

impl<H: Hasher> fri::PublicCoin for ProverChannel<H> {
    type Hasher = H;

    fn fri_layer_commitments(&self) -> &[H::Digest] {
        assert!(!self.fri_roots.is_empty(), "FRI layers are not set");
        &self.fri_roots
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn find_pow_nonce<H: Hasher>(seed: H::Digest, grinding_factor: u32) -> (H::Digest, u64) {
    #[cfg(not(feature = "concurrent"))]
    let nonce = (1..u64::MAX)
        .find(|nonce| {
            let result = H::merge_with_int(seed, *nonce);
            let bytes: &[u8] = result.as_ref();
            u64::from_le_bytes(bytes[..8].try_into().unwrap()).trailing_zeros() >= grinding_factor
        })
        .expect("nonce not found");

    #[cfg(feature = "concurrent")]
    let nonce = (1..u64::MAX)
        .into_par_iter()
        .find_any(|nonce| {
            let result = H::merge_with_int(seed, *nonce);
            let bytes: &[u8] = result.as_ref();
            u64::from_le_bytes(bytes[..8].try_into().unwrap()).trailing_zeros() >= grinding_factor
        })
        .expect("nonce not found");

    let result = H::merge_with_int(seed, nonce);
    (result, nonce)
}
