// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    folding::{apply_drp, fold_positions},
    proof::{FriProof, FriProofLayer},
    utils::hash_values,
    FriOptions,
};
use core::marker::PhantomData;
use crypto::{ElementHasher, Hasher, MerkleTree};
use math::{FieldElement, StarkField};
use utils::{collections::Vec, flatten_vector_elements, group_slice_elements, transpose_slice};

mod channel;
pub use channel::{DefaultProverChannel, ProverChannel};

#[cfg(test)]
mod tests;

// TYPES AND INTERFACES
// ================================================================================================

/// Implements the prover component of the FRI protocol.
///
/// Given evaluations of a function *f* over domain *D* (`evaluations`), a FRI prover generates
/// a proof that *f* is a polynomial of some bounded degree *d*, such that *d* < |*D*| / 2. The
/// proof is succinct: it exponentially smaller than `evaluations` and the verifier can verify it
/// exponentially faster than it would have taken them to read all `evaluations`.
///
/// The prover is parametrized with the following types:
///
/// * `B` specifies the base field of the STARK protocol.
/// * `E` specifies the field in which the FRI protocol is executed. This can be the same as the
///   base field `B`, but it can also be an extension of the base field in cases when the base
///   field is too small to provide desired security level for the FRI protocol.
/// * `C` specifies the type used to simulate prover-verifier interaction.
/// * `H` specifies the hash function used to build layer Merkle trees. The same hash function
///   must be used in the prover channel to generate pseudo random values.
///
/// Proof generation is performed in two phases: commit phase and query phase.
///
/// # Commit phase
/// During the commit phase, which is executed via [build_layers()](FriProver::build_layers())
/// function, the prover repeatedly applies a degree-respecting projection (DRP) to `evaluations`
/// (see [folding](crate::folding)). With every application of the DRP, the degree of the function
/// *f* (and size of the domain over which it is evaluated) is reduced by the `folding_factor`
/// until the remaining evaluations fit into a vector of at most `max_remainder_size` elements.
///
/// At each layer of reduction, the prover commits to the current set of evaluations. This is done
/// by building a Merkle tree from the evaluations and sending the root of the tree to the verifier
/// (via [ProverChannel]). The Merkle tree is build in such a way that all evaluations needed to
/// compute a single value in the next FRI layer are grouped into the same leaf (the number of
/// evaluations needed to compute a single element in the next FRI layer is equal to the
/// `folding_factor`). This allows us to decommit all these values using a single Merkle
/// authentication path.
///
/// After committing to the set of evaluations at the current layer, the prover draws a random
/// field element α from the channel, and uses it to build the next FRI layer. In the interactive
/// version of the protocol, the verifier draws α uniformly at random from the entire field and
/// sends it to the prover. In the non-interactive version, α is pseudo-randomly generated based
/// on the values the prover has written into the channel up to that point.
///
/// The prover keeps all FRI layers (consisting of evaluations and corresponding Merkle trees) in
/// its internal state.
///
/// # Query phase
/// In the query phase, which is executed via [build_proof()](FriProver::build_proof()) function,
/// the prover receives a set of positions in the domain *D* from the verifier. The prover then
/// decommits evaluations corresponding to these positions across all FRI layers (except for the
/// remainder layer) and builds a [FriProof] from these evaluations. The remainder is included in
/// the proof in its entirety.
///
/// In the interactive version of the protocol, the verifier draws the position uniformly at
/// random from domain *D*. In the non-interactive version, the positions are pseudo-randomly
/// selected based on the values the prover has written into the channel up to that point.
///
/// Since the positions are drawn from domain *D*, they apply directly only to the first FRI
/// layer. To map these positions to the positions in all subsequent layers, the prover uses
/// [fold_positions] procedure.
///
/// After the proof is generated, the prover deletes all internally stored FRI layers.
///
/// Calling [build_layers()](FriProver::build_layers()) when the internal state is dirty, or
/// calling [build_proof()](FriProver::build_proof()) on a clean state will result in a panic.
pub struct FriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = B>,
{
    options: FriOptions,
    layers: Vec<FriLayer<B, E, H>>,
    _channel: PhantomData<C>,
}

struct FriLayer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    tree: MerkleTree<H>,
    evaluations: Vec<E>,
    _base_field: PhantomData<B>,
}

// PROVER IMPLEMENTATION
// ================================================================================================

impl<B, E, C, H> FriProver<B, E, C, H>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = B>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new FRI prover instantiated with the provided `options`.
    pub fn new(options: FriOptions) -> Self {
        FriProver {
            options,
            layers: Vec::new(),
            _channel: PhantomData,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns folding factor for this prover.
    pub fn folding_factor(&self) -> usize {
        self.options.folding_factor()
    }

    /// Returns offset of the domain over which FRI protocol is executed by this prover.
    pub fn domain_offset(&self) -> B {
        self.options.domain_offset()
    }

    /// Returns number of FRI layers computed during the last execution of the
    /// [build_layers()](FriProver::build_layers()) method.
    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }

    /// Clears a vector of internally stored layers.
    pub fn reset(&mut self) {
        self.layers.clear();
    }

    // COMMIT PHASE
    // --------------------------------------------------------------------------------------------
    /// Executes the commit phase of the FRI protocol.
    ///
    /// During this phase we repeatedly apply a degree-respecting projection (DRP) to the
    /// `evaluations` which contain evaluations some function *f* over domain *D*. With every
    /// application of the DRP the degree of the function (and size of the domain) is reduced by
    /// `folding_factor` until the remaining evaluations can fit into a vector of at most
    /// `max_remainder_size`. At each layer of reduction the current evaluations are committed to
    /// using a Merkle tree, and the root of this tree is written into the channel. After this the
    /// prover draws a random field element α from the channel, and uses it in the next application
    /// of the DRP.
    ///
    /// # Panics
    /// Panics if the prover state is dirty (the vector of layers is not empty).
    pub fn build_layers(&mut self, channel: &mut C, mut evaluations: Vec<E>) {
        assert!(
            self.layers.is_empty(),
            "a prior proof generation request has not been completed yet"
        );

        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // is small enough; + 1 is for the remainder
        for _ in 0..self.options.num_fri_layers(evaluations.len()) + 1 {
            match self.folding_factor() {
                4 => self.build_layer::<4>(channel, &mut evaluations),
                8 => self.build_layer::<8>(channel, &mut evaluations),
                16 => self.build_layer::<16>(channel, &mut evaluations),
                _ => unimplemented!("folding factor {} is not supported", self.folding_factor()),
            }
        }

        // make sure remainder length does not exceed max allowed value
        let last_layer = &self.layers[self.layers.len() - 1];
        let remainder_size = last_layer.evaluations.len();
        debug_assert!(
            remainder_size <= self.options.max_remainder_size(),
            "last FRI layer cannot exceed {} elements, but was {} elements",
            self.options.max_remainder_size(),
            remainder_size
        );
    }

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(&mut self, channel: &mut C, evaluations: &mut Vec<E>) {
        // commit to the evaluations at the current layer; we do this by first transposing the
        // evaluations into a matrix of N columns, and then building a Merkle tree from the
        // rows of this matrix; we do this so that we could de-commit to N values with a single
        // Merkle authentication path.
        let transposed_evaluations = transpose_slice(evaluations);
        let hashed_evaluations = hash_values::<H, E, N>(&transposed_evaluations);
        let evaluation_tree =
            MerkleTree::<H>::new(hashed_evaluations).expect("failed to construct FRI layer tree");
        channel.commit_fri_layer(*evaluation_tree.root());

        // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
        // projection to reduce the degree of evaluations by N
        let alpha = channel.draw_fri_alpha();
        *evaluations = apply_drp(&transposed_evaluations, self.domain_offset(), alpha);

        self.layers.push(FriLayer {
            tree: evaluation_tree,
            evaluations: flatten_vector_elements(transposed_evaluations),
            _base_field: PhantomData,
        });
    }

    // QUERY PHASE
    // --------------------------------------------------------------------------------------------
    /// Executes query phase of FRI protocol.
    ///
    /// For each of the provided `positions`, corresponding evaluations from each of the layers
    /// (excluding the remainder layer) are recorded into the proof together with Merkle
    /// authentication paths from the root of layer commitment trees. For the remainder, we include
    /// the whole set of evaluations into the proof.
    ///
    /// # Panics
    /// Panics is the prover state is clean (no FRI layers have been build yet).
    pub fn build_proof(&mut self, positions: &[usize]) -> FriProof {
        assert!(
            !self.layers.is_empty(),
            "FRI layers have not been built yet"
        );
        let mut positions = positions.to_vec();
        let mut domain_size = self.layers[0].evaluations.len();
        let folding_factor = self.options.folding_factor();

        // for all FRI layers, except the last one, record tree root, determine a set of query
        // positions, and query the layer at these positions.
        let mut layers = Vec::with_capacity(self.layers.len());
        for i in 0..self.layers.len() - 1 {
            positions = fold_positions(&positions, domain_size, folding_factor);

            // sort of a static dispatch for folding_factor parameter
            let proof_layer = match folding_factor {
                4 => query_layer::<B, E, H, 4>(&self.layers[i], &positions),
                8 => query_layer::<B, E, H, 8>(&self.layers[i], &positions),
                16 => query_layer::<B, E, H, 16>(&self.layers[i], &positions),
                _ => unimplemented!("folding factor {} is not supported", folding_factor),
            };

            layers.push(proof_layer);
            domain_size /= folding_factor;
        }

        // use the remaining polynomial values directly as proof; last layer values contain
        // remainder in transposed form - so, we un-transpose it first
        let last_values = &self.layers[self.layers.len() - 1].evaluations;
        let mut remainder = E::zeroed_vector(last_values.len());
        let n = last_values.len() / folding_factor;
        for i in 0..n {
            for j in 0..folding_factor {
                remainder[i + n * j] = last_values[i * folding_factor + j];
            }
        }

        // clear layers so that another proof can be generated
        self.reset();

        FriProof::new(layers, remainder, 1)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a single proof layer by querying the evaluations of the passed in FRI layer at the
/// specified positions.
fn query_layer<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher, const N: usize>(
    layer: &FriLayer<B, E, H>,
    positions: &[usize],
) -> FriProofLayer {
    // build Merkle authentication paths for all query positions
    let proof = layer
        .tree
        .prove_batch(positions)
        .expect("failed to generate a Merkle proof for FRI layer queries");

    // build a list of polynomial evaluations at each position; since evaluations in FRI layers
    // are stored in transposed form, a position refers to N evaluations which are committed
    // in a single leaf
    let evaluations: &[[E; N]] = group_slice_elements(&layer.evaluations);
    let mut queried_values: Vec<[E; N]> = Vec::with_capacity(positions.len());
    for &position in positions.iter() {
        queried_values.push(evaluations[position]);
    }

    FriProofLayer::new(queried_values, proof)
}
