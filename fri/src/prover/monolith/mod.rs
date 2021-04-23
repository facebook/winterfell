// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{utils, FriOptions, FriProof, FriProofLayer, ProverChannel};
use crypto::{Hasher, MerkleTree};
use math::field::{FieldElement, StarkField};
use std::marker::PhantomData;

#[cfg(not(feature = "concurrent"))]
use crate::folding::quartic;

#[cfg(feature = "concurrent")]
use crate::folding::quartic::concurrent as quartic;

#[cfg(test)]
mod tests;

const FOLDING_FACTOR: usize = crate::options::FOLDING_FACTOR;

// TYPES AND INTERFACES
// ================================================================================================

pub struct FriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    C: ProverChannel<Hasher = H>,
    H: Hasher,
{
    options: FriOptions<B>,
    layers: Vec<FriLayer<B, E>>,
    _coin: PhantomData<C>,
    _hasher: PhantomData<H>,
}

struct FriLayer<B, E>
where
    B: StarkField,
    E: FieldElement + From<B>,
{
    tree: MerkleTree,
    evaluations: Vec<[E; FOLDING_FACTOR]>,
    _b_marker: PhantomData<B>,
}

// PROVER IMPLEMENTATION
// ================================================================================================

impl<B, E, C, H> FriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement + From<B>,
    C: ProverChannel<Hasher = H>,
    H: Hasher,
{
    pub fn new(options: FriOptions<B>) -> Self {
        FriProver {
            options,
            layers: Vec::new(),
            _coin: PhantomData,
            _hasher: PhantomData,
        }
    }

    /// Executes commit phase of FRI protocol which recursively applies a degree-respecting projection
    /// to evaluations of some function F over a larger domain. The degree of the function implied
    /// but evaluations is reduced by FOLDING_FACTOR at every step until the remaining evaluations
    /// can fit into a vector of at most max_remainder_length. At each layer of recursion the
    /// current evaluations are committed to using a Merkle tree, and the root of this tree is used
    /// to derive randomness for the subsequent application of degree-respecting projection.
    pub fn build_layers(&mut self, channel: &mut C, mut evaluations: Vec<E>, domain: &[B]) {
        assert!(
            evaluations.len() == domain.len(),
            "number of evaluations must match the domain size"
        );
        assert_eq!(
            domain[0],
            self.options.domain_offset(),
            "inconsistent domain offset; expected {}, but was: {}",
            self.options.domain_offset(),
            domain[0]
        );
        assert!(
            self.layers.is_empty(),
            "a prior proof generation request has not been completed yet"
        );

        let hash_fn = H::hash_fn();

        // reduce the degree by 4 at each iteration until the remaining polynomial is small enough;
        // + 1 is for the remainder
        for depth in 0..self.options.num_fri_layers(domain.len()) + 1 {
            // commit to the evaluations at the current layer; we do this by first transposing the
            // evaluations into a matrix of 4 columns, and then building a Merkle tree from the
            // rows of this matrix; we do this so that we could de-commit to 4 values with a sing
            // Merkle authentication path.
            let transposed_evaluations = quartic::transpose(&evaluations, 1);
            let hashed_evaluations = quartic::hash_values(&transposed_evaluations, hash_fn);
            let evaluation_tree = MerkleTree::new(hashed_evaluations, hash_fn);
            channel.commit_fri_layer(*evaluation_tree.root());

            // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
            // projection to reduce the degree of evaluations by 4
            let alpha = channel.draw_fri_alpha::<E>(depth as usize);
            evaluations = apply_drp(&transposed_evaluations, domain, depth, alpha);

            self.layers.push(FriLayer {
                tree: evaluation_tree,
                evaluations: transposed_evaluations,
                _b_marker: PhantomData,
            });
        }

        // make sure remainder length does not exceed max allowed value
        let last_layer = &self.layers[self.layers.len() - 1];
        let remainder_length = last_layer.evaluations.len() * FOLDING_FACTOR;
        debug_assert!(
            remainder_length <= self.options.max_remainder_length(),
            "last FRI layer cannot exceed {} elements, but was {} elements",
            self.options.max_remainder_length(),
            remainder_length
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
            positions =
                utils::fold_positions(&positions, domain_size, self.options.folding_factor());

            let proof = self.layers[i].tree.prove_batch(&positions);

            let mut queried_values: Vec<[E; FOLDING_FACTOR]> = Vec::with_capacity(positions.len());
            for &position in positions.iter() {
                queried_values.push(self.layers[i].evaluations[position]);
            }

            layers.push(FriProofLayer {
                values: queried_values
                    .into_iter()
                    .map(|v| E::elements_as_bytes(&v).to_vec())
                    .collect(),
                paths: proof.nodes,
                depth: proof.depth,
            });
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

        FriProof {
            layers,
            rem_values: E::elements_as_bytes(&remainder).to_vec(),
            partitioned: false,
        }
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

/// Applies degree-respecting projection to the `evaluations` reducing the degree of evaluations
/// by FOLDING_FACTOR. This is equivalent to the following:
/// - Let `evaluations` contain the evaluations of polynomial f(x) of degree k
/// - Group coefficients of f so that f(x) = a(x) + x * b(x) + x^2 * c(x) + x^3 * d(x)
/// - Compute random linear combination of a, b, c, d as:
///   f'(x) = a + alpha * b + alpha^2 * c + alpha^3 * d, where alpha is a random coefficient
/// - evaluate f'(x) on a domain which consists of x^4 from the original domain (and thus is
///   1/4 the size)
/// note: that to compute an x in the new domain, we need 4 values from the old domain:
/// x^{1/4}, x^{2/4}, x^{3/4}, x
fn apply_drp<B, E>(
    evaluations: &[[E; FOLDING_FACTOR]],
    domain: &[B],
    depth: usize,
    alpha: E,
) -> Vec<E>
where
    B: StarkField,
    E: FieldElement + From<B>,
{
    let domain_stride = usize::pow(FOLDING_FACTOR, depth as u32);
    let xs = quartic::transpose(domain, domain_stride);

    let polys = quartic::interpolate_batch(&xs, &evaluations);

    quartic::evaluate_batch(&polys, alpha)
}
