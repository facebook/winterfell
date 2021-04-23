// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{
    proof::{Commitments, Context, OodEvaluationFrame, Queries, StarkProof},
    ComputationContext, EvaluationFrame, PublicCoin,
};
use crypto::{DefaultRandomElementGenerator, Hasher};
use fri::{self, FriProof};
use math::{
    field::{FieldElement, StarkField},
    utils::log2,
};
use std::{convert::TryInto, marker::PhantomData};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// TYPES AND INTERFACES
// ================================================================================================

pub struct ProverChannel<H: Hasher> {
    context: ComputationContext,
    trace_root: Option<[u8; 32]>,
    constraint_root: Option<[u8; 32]>,
    fri_roots: Vec<[u8; 32]>,
    query_seed: Option<[u8; 32]>,
    pow_nonce: u64,
    _hasher: PhantomData<H>,
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
            _hasher: PhantomData,
        }
    }

    /// Commits the prover the extended execution trace.
    pub fn commit_trace(&mut self, trace_root: [u8; 32]) {
        assert!(
            self.trace_root.is_none(),
            "trace root has already been committed"
        );
        self.trace_root = Some(trace_root);
    }

    /// Commits the prover the the constraint evaluations.
    pub fn commit_constraints(&mut self, constraint_root: [u8; 32]) {
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
        let seed = build_query_seed::<H>(&self.fri_roots);
        let (seed, nonce) = find_pow_nonce::<H>(seed, options.grinding_factor());
        self.query_seed = Some(seed);
        self.pow_nonce = nonce;
    }

    /// Builds a proof from the previously committed values as well as values
    /// passed in to this method
    pub fn build_proof<B: StarkField, E: FieldElement + From<B>>(
        self,
        trace_queries: Queries,
        constraint_queries: Queries,
        ood_frame: EvaluationFrame<E>,
        fri_proof: FriProof,
    ) -> StarkProof {
        StarkProof {
            context: Context {
                lde_domain_depth: log2(self.context.lde_domain_size()) as u8,
                ce_blowup_factor: self.context.ce_blowup_factor() as u8,
                field_modulus_bytes: B::get_modulus_le_bytes(),
                options: self.context().options().clone(),
            },
            commitments: Commitments {
                trace_root: self.trace_root.unwrap(),
                constraint_root: self.constraint_root.unwrap(),
                fri_roots: self.fri_roots,
            },
            trace_queries,
            constraint_queries,
            ood_frame: OodEvaluationFrame {
                trace_at_z1: E::elements_as_bytes(&ood_frame.current).to_vec(),
                trace_at_z2: E::elements_as_bytes(&ood_frame.next).to_vec(),
            },
            fri_proof,
            pow_nonce: self.pow_nonce,
        }
    }
}

impl<H: Hasher> fri::ProverChannel for ProverChannel<H> {
    type Hasher = H;

    /// Commits the prover to the a FRI layer.
    fn commit_fri_layer(&mut self, layer_root: [u8; 32]) {
        self.fri_roots.push(layer_root);
    }
}

// PUBLIC COIN IMPLEMENTATION
// ================================================================================================

impl<H: Hasher> PublicCoin for ProverChannel<H> {
    type Hasher = H;

    fn context(&self) -> &ComputationContext {
        &self.context
    }

    fn constraint_seed(&self) -> [u8; 32] {
        assert!(self.trace_root.is_some(), "constraint seed is not set");
        self.trace_root.unwrap()
    }

    fn composition_seed(&self) -> [u8; 32] {
        assert!(
            self.constraint_root.is_some(),
            "composition seed is not set"
        );
        self.constraint_root.unwrap()
    }

    fn query_seed(&self) -> [u8; 32] {
        assert!(self.query_seed.is_some(), "query seed is not set");
        self.query_seed.unwrap()
    }
}

impl<H: Hasher> fri::PublicCoin for ProverChannel<H> {
    type RandomElementGenerator = DefaultRandomElementGenerator<H>;

    fn fri_layer_commitments(&self) -> &[[u8; 32]] {
        assert!(!self.fri_roots.is_empty(), "FRI layers are not set");
        &self.fri_roots
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_query_seed<H: Hasher>(fri_roots: &[[u8; 32]]) -> [u8; 32] {
    let hash_fn = H::hash_fn();
    // combine roots of all FIR layers into a single array of bytes
    let mut root_bytes: Vec<u8> = Vec::with_capacity(fri_roots.len() * 32);
    for root in fri_roots.iter() {
        root.iter().for_each(|&v| root_bytes.push(v));
    }

    // hash the array of bytes into a single 32-byte value
    let mut query_seed = [0u8; 32];
    hash_fn(&root_bytes, &mut query_seed);

    query_seed
}

fn find_pow_nonce<H: Hasher>(seed: [u8; 32], grinding_factor: u32) -> ([u8; 32], u64) {
    let hash_fn = H::hash_fn();
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&seed);

    #[cfg(not(feature = "concurrent"))]
    let nonce = (1..u64::MAX)
        .find(|nonce| {
            let mut result = [0u8; 32];
            let mut buf = buf;

            buf[56..].copy_from_slice(&nonce.to_le_bytes());
            hash_fn(&buf, &mut result);
            u64::from_le_bytes(result[..8].try_into().unwrap()).trailing_zeros() >= grinding_factor
        })
        .expect("nonce not found");

    #[cfg(feature = "concurrent")]
    let nonce = (1..u64::MAX)
        .into_par_iter()
        .find_any(|nonce| {
            let mut result = [0u8; 32];
            let mut buf = buf;

            buf[56..].copy_from_slice(&nonce.to_le_bytes());
            hash_fn(&buf, &mut result);
            u64::from_le_bytes(result[..8].try_into().unwrap()).trailing_zeros() >= grinding_factor
        })
        .expect("nonce not found");

    let mut result = [0u8; 32];
    buf[56..].copy_from_slice(&nonce.to_le_bytes());
    hash_fn(&buf, &mut result);

    (result, nonce)
}
