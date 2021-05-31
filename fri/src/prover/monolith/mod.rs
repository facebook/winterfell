// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    folding::apply_drp, utils::fold_positions, FriOptions, FriProof, FriProofLayer, ProverChannel,
};
use crypto::{Hasher, MerkleTree};
use math::field::{FieldElement, StarkField};
use std::marker::PhantomData;
use utils::{iter_mut, transpose_slice, uninit_vector};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

#[cfg(test)]
mod tests;

const FOLDING_FACTOR: usize = crate::options::FOLDING_FACTOR;

// TYPES AND INTERFACES
// ================================================================================================

pub struct FriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: ProverChannel<E, Hasher = H>,
    H: Hasher,
{
    options: FriOptions,
    layers: Vec<FriLayer<B, E, H>>,
    _coin: PhantomData<C>,
}

struct FriLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    evaluations: Vec<[E; FOLDING_FACTOR]>,
    _base_field: PhantomData<B>,
}

// PROVER IMPLEMENTATION
// ================================================================================================

impl<B, E, C, H> FriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: ProverChannel<E, Hasher = H>,
    H: Hasher,
{
    pub fn new(options: FriOptions) -> Self {
        FriProver {
            options,
            layers: Vec::new(),
            _coin: PhantomData,
        }
    }

    /// Executes commit phase of FRI protocol which recursively applies a degree-respecting projection
    /// to evaluations of some function F over a larger domain. The degree of the function implied
    /// but evaluations is reduced by folding_factor at every step until the remaining evaluations
    /// can fit into a vector of at most max_remainder_length. At each layer of recursion the
    /// current evaluations are committed to using a Merkle tree, and the root of this tree is used
    /// to derive randomness for the subsequent application of degree-respecting projection.
    pub fn build_layers(&mut self, channel: &mut C, mut evaluations: Vec<E>, domain: &[B]) {
        assert_eq!(
            evaluations.len(),
            domain.len(),
            "number of evaluations must match the domain size"
        );
        assert_eq!(
            domain[0],
            self.options.domain_offset(),
            "inconsistent domain offset; expected {}, but was: {}",
            self.options.domain_offset::<B>(),
            domain[0]
        );
        assert!(
            self.layers.is_empty(),
            "a prior proof generation request has not been completed yet"
        );

        // reduce the degree by 4 at each iteration until the remaining polynomial is small enough;
        // + 1 is for the remainder
        for _ in 0..self.options.num_fri_layers(domain.len()) + 1 {
            // commit to the evaluations at the current layer; we do this by first transposing the
            // evaluations into a matrix of 4 columns, and then building a Merkle tree from the
            // rows of this matrix; we do this so that we could de-commit to 4 values with a sing
            // Merkle authentication path.
            let transposed_evaluations = transpose_slice(&evaluations);
            let hashed_evaluations = hash_values::<H, E, 4>(&transposed_evaluations);
            let evaluation_tree = MerkleTree::<H>::new(hashed_evaluations);
            channel.commit_fri_layer(*evaluation_tree.root());

            // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
            // projection to reduce the degree of evaluations by 4
            let alpha = channel.draw_fri_alpha();
            //evaluations = apply_drp(&transposed_evaluations, domain[0], alpha);
            evaluations = apply_drp(&transposed_evaluations, domain[0], alpha);

            self.layers.push(FriLayer {
                tree: evaluation_tree,
                evaluations: transposed_evaluations,
                _base_field: PhantomData,
            });
        }

        // make sure remainder length does not exceed max allowed value
        let last_layer = &self.layers[self.layers.len() - 1];
        let remainder_size = last_layer.evaluations.len() * FOLDING_FACTOR;
        debug_assert!(
            remainder_size <= self.options.max_remainder_size(),
            "last FRI layer cannot exceed {} elements, but was {} elements",
            self.options.max_remainder_size(),
            remainder_size
        );
    }

    /// Executes query phase of FRI protocol. For each of the provided `positions`, corresponding
    /// evaluations from each of the layers are recorded into the proof together with Merkle
    /// authentication paths from the root of layer commitment trees.
    pub fn build_proof(&mut self, positions: &[usize]) -> FriProof {
        assert!(
            !self.layers.is_empty(),
            "FRI layers have not been built yet"
        );
        let mut positions = positions.to_vec();
        let mut domain_size = self.layers[0].evaluations.len() * FOLDING_FACTOR;

        // for all trees, except the last one, record tree root, authentication paths
        // to row evaluations, and values for row evaluations
        let mut layers = Vec::with_capacity(self.layers.len());
        for i in 0..self.layers.len() - 1 {
            positions = fold_positions(&positions, domain_size, self.options.folding_factor());

            let proof = self.layers[i].tree.prove_batch(&positions);

            let mut queried_values: Vec<[E; FOLDING_FACTOR]> = Vec::with_capacity(positions.len());
            for &position in positions.iter() {
                queried_values.push(self.layers[i].evaluations[position]);
            }

            layers.push(FriProofLayer::new(queried_values, proof));
            domain_size /= FOLDING_FACTOR;
        }

        // use the remaining polynomial values directly as proof
        // TODO: write remainder to the proof in transposed form?
        let last_values = &self.layers[self.layers.len() - 1].evaluations;
        let n = last_values.len();
        let mut remainder = E::zeroed_vector(n * FOLDING_FACTOR);
        for i in 0..last_values.len() {
            remainder[i] = last_values[i][0];
            remainder[i + n] = last_values[i][1];
            remainder[i + n * 2] = last_values[i][2];
            remainder[i + n * 3] = last_values[i][3];
        }

        // clear layers so that another proof can be generated
        self.reset();

        FriProof::new(layers, remainder, 1)
    }

    /// Returns number of FRI layers computed during the last execution of build_layers() method
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }

    /// Clears a vector of internally stored layers.
    pub fn reset(&mut self) {
        self.layers.clear();
    }
}

// HELPER FUNCTIONS
// ================================================================================================

pub fn hash_values<H: Hasher, E: FieldElement, const N: usize>(
    values: &[[E; N]],
) -> Vec<H::Digest> {
    let mut result: Vec<H::Digest> = uninit_vector(values.len());
    iter_mut!(result, 1024).zip(values).for_each(|(r, v)| {
        *r = H::hash_elements(v);
    });
    result
}
