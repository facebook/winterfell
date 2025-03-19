// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crypto::{ElementHasher, Hasher, VectorCommitment};
use math::{fft, FieldElement};
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{
    flatten_vector_elements, group_slice_elements, iter_mut, transpose_slice, uninit_vector,
};

use crate::{
    folding::{apply_drp, fold_positions},
    proof::{FriProof, FriProofLayer},
    FriOptions,
};

mod channel;
pub use channel::{DefaultProverChannel, ProverChannel};

#[cfg(test)]
mod tests;

// TYPES AND INTERFACES
// ================================================================================================

/// Implements the prover component of the FRI protocol.
///
/// Given evaluations of a function *f* over domain *D* (`evaluations`), a FRI prover generates
/// a proof that *f* is a polynomial of some bounded degree *d*, such that
/// *d* < |*D*| / *blowup_factor*.
/// The proof is succinct: it exponentially smaller than `evaluations` and the verifier can verify
/// it exponentially faster than it would have taken them to read all `evaluations`.
///
/// The prover is parametrized with the following types:
///
/// * `E` specifies the field in which the FRI protocol is executed.
/// * `C` specifies the type used to simulate prover-verifier interaction.
/// * `H` specifies the hash function used to build for each layer the vector of values committed to
///   using the specified vector commitment scheme. The same hash function must be used in the
///   prover channel to generate pseudo random values.
/// * `V` specifies the vector commitment scheme used in order to commit to each layer.
///
/// Proof generation is performed in two phases: commit phase and query phase.
///
/// # Commit phase
/// During the commit phase, which is executed via [build_layers()](FriProver::build_layers())
/// function, the prover repeatedly applies a degree-respecting projection (DRP) to `evaluations`
/// (see [folding](crate::folding)). With every application of the DRP, the degree of the function
/// *f* (and size of the domain over which it is evaluated) is reduced by the `folding_factor`
/// until the remaining evaluations correspond to a polynomial, called remainder polynomial, with
/// a number of coefficients less than or equal to `remainder_max_degree_plus_1`.
///
/// At each layer of reduction, the prover commits to the current set of evaluations. This is done
/// by building a vector commitment to hashed evaluations and sending the commitment string
/// to the verifier (via [ProverChannel]). The vector commitment is build in such a way that all
/// evaluations needed to compute a single value in the next FRI layer are grouped into the same
/// leaf (the number of evaluations needed to compute a single element in the next FRI layer is
/// equal to the `folding_factor`). This allows us to decommit all these values using a single
/// individual opening proof.
///
/// After committing to the set of evaluations at the current layer, the prover draws a random
/// field element α from the channel, and uses it to build the next FRI layer. In the interactive
/// version of the protocol, the verifier draws α uniformly at random from the entire field and
/// sends it to the prover. In the non-interactive version, α is pseudo-randomly generated based
/// on the values the prover has written into the channel up to that point.
///
/// The prover keeps all FRI layers (consisting of evaluations and corresponding vector
/// commitments) in its internal state.
///
/// # Query phase
/// In the query phase, which is executed via [build_proof()](FriProver::build_proof()) function,
/// the prover receives a set of positions in the domain *D* from the verifier. The prover then
/// decommits evaluations corresponding to these positions across all FRI layers (except for the
/// remainder layer) and builds a [FriProof] from these evaluations. The remainder polynomial
/// is included in the proof in its entirety.
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
pub struct FriProver<E, C, H, V>
where
    E: FieldElement,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    options: FriOptions,
    layers: Vec<FriLayer<E, H, V>>,
    remainder_poly: FriRemainder<E>,
    _channel: PhantomData<C>,
}

struct FriLayer<E: FieldElement, H: Hasher, V: VectorCommitment<H>> {
    commitment: V,
    evaluations: Vec<E>,
    _h: PhantomData<H>,
}

struct FriRemainder<E: FieldElement>(Vec<E>);

// PROVER IMPLEMENTATION
// ================================================================================================

impl<E, C, H, V> FriProver<E, C, H, V>
where
    E: FieldElement,
    C: ProverChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new FRI prover instantiated with the provided `options`.
    pub fn new(options: FriOptions) -> Self {
        FriProver {
            options,
            layers: Vec::new(),
            remainder_poly: FriRemainder(vec![]),
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
    pub fn domain_offset(&self) -> E::BaseField {
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
        self.remainder_poly.0.clear();
    }

    // COMMIT PHASE
    // --------------------------------------------------------------------------------------------
    /// Executes the commit phase of the FRI protocol.
    ///
    /// During this phase we repeatedly apply a degree-respecting projection (DRP) to
    /// `evaluations` which contain evaluations of some function *f* over domain *D*. With every
    /// application of the DRP the degree of the function (and size of the domain) is reduced by
    /// `folding_factor` until the remaining evaluations can be represented by a remainder
    /// polynomial with at most `remainder_max_degree_plus_1` number of coefficients.
    /// At each layer of reduction the current evaluations are committed to using a vector
    /// commitment scheme, and the commitment string of this vector commitment is written into
    /// the channel. After this the prover draws a random field element α from the channel, and
    /// uses it in the next application of the DRP.
    ///
    /// # Panics
    /// Panics if the prover state is dirty (the vector of layers is not empty).
    pub fn build_layers(&mut self, channel: &mut C, mut evaluations: Vec<E>) {
        assert!(
            self.layers.is_empty(),
            "a prior proof generation request has not been completed yet"
        );

        // reduce the degree by folding_factor at each iteration until the remaining polynomial
        // has small enough degree
        for _ in 0..self.options.num_fri_layers(evaluations.len()) {
            match self.folding_factor() {
                2 => self.build_layer::<2>(channel, &mut evaluations),
                4 => self.build_layer::<4>(channel, &mut evaluations),
                8 => self.build_layer::<8>(channel, &mut evaluations),
                16 => self.build_layer::<16>(channel, &mut evaluations),
                _ => unimplemented!("folding factor {} is not supported", self.folding_factor()),
            }
        }

        self.set_remainder(channel, &mut evaluations);
    }

    /// Builds a single FRI layer by first committing to the `evaluations`, then drawing a random
    /// alpha from the channel and use it to perform degree-respecting projection.
    fn build_layer<const N: usize>(&mut self, channel: &mut C, evaluations: &mut Vec<E>) {
        // commit to the evaluations at the current layer; we do this by first transposing the
        // evaluations into a matrix of N columns, then hashing each row into a digest, and finally
        // commiting to vector of these digests; we do this so that we could de-commit to N values
        // with a single opening proof.
        let transposed_evaluations = transpose_slice(evaluations);
        let evaluation_vector_commitment =
            build_layer_commitment::<_, _, V, N>(&transposed_evaluations)
                .expect("failed to construct FRI layer commitment");
        channel.commit_fri_layer(evaluation_vector_commitment.commitment());

        // draw a pseudo-random coefficient from the channel, and use it in degree-respecting
        // projection to reduce the degree of evaluations by N
        let alpha = channel.draw_fri_alpha();
        *evaluations = apply_drp(&transposed_evaluations, self.domain_offset(), alpha);
        self.layers.push(FriLayer {
            commitment: evaluation_vector_commitment,
            evaluations: flatten_vector_elements(transposed_evaluations),
            _h: PhantomData,
        });
    }

    /// Creates remainder polynomial in coefficient form from a vector of `evaluations` over a
    /// domain.
    ///
    /// We commit to the coefficients of the remainder polynomial in reverse order so that
    /// evaluating the remainder polynomial on the verifier's end, using Horner's evaluation
    /// method, becomes easier.
    fn set_remainder(&mut self, channel: &mut C, evaluations: &mut [E]) {
        let inv_twiddles = fft::get_inv_twiddles(evaluations.len());
        fft::interpolate_poly_with_offset(evaluations, &inv_twiddles, self.options.domain_offset());
        let remainder_poly_size = evaluations.len() / self.options.blowup_factor();
        let remainder_poly: Vec<_> =
            evaluations[..remainder_poly_size].iter().copied().rev().collect();
        let commitment = <H as ElementHasher>::hash_elements(&remainder_poly);
        channel.commit_fri_layer(commitment);
        self.remainder_poly = FriRemainder(remainder_poly);
    }

    // QUERY PHASE
    // --------------------------------------------------------------------------------------------
    /// Executes query phase of FRI protocol.
    ///
    /// For each of the provided `positions`, corresponding evaluations from each of the layers
    /// (excluding the remainder layer) are recorded into the proof together with a batch opening
    /// proof against the sent vector commitment. For the remainder, we send the whole remainder
    /// polynomial resulting from interpolating the remainder layer evaluations. The coefficients
    /// of the remainder polynomial are sent in reverse order so as to make evaluating it on
    /// the verifier's end, using Horner's evaluation method, easier.
    ///
    /// # Panics
    /// Panics is the prover state is clean (no FRI layers have been build yet).
    pub fn build_proof(&mut self, positions: &[usize]) -> FriProof {
        assert!(!self.remainder_poly.0.is_empty(), "FRI layers have not been built yet");

        let mut layers = Vec::with_capacity(self.layers.len());

        if !self.layers.is_empty() {
            let mut positions = positions.to_vec();
            let mut domain_size = self.layers[0].evaluations.len();
            let folding_factor = self.options.folding_factor();

            // for all FRI layers, except the last one, record tree root, determine a set of query
            // positions, and query the layer at these positions.
            for i in 0..self.layers.len() {
                positions = fold_positions(&positions, domain_size, folding_factor);

                // sort of a static dispatch for folding_factor parameter
                let proof_layer = match folding_factor {
                    2 => query_layer::<E, H, V, 2>(&self.layers[i], &positions),
                    4 => query_layer::<E, H, V, 4>(&self.layers[i], &positions),
                    8 => query_layer::<E, H, V, 8>(&self.layers[i], &positions),
                    16 => query_layer::<E, H, V, 16>(&self.layers[i], &positions),
                    _ => unimplemented!("folding factor {} is not supported", folding_factor),
                };

                layers.push(proof_layer);
                domain_size /= folding_factor;
            }
        }

        // use the remaining polynomial values directly as proof
        let remainder = self.remainder_poly.0.clone();

        // clear layers so that another proof can be generated
        self.reset();

        FriProof::new(layers, remainder, 1)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Builds a single proof layer by querying the evaluations of the passed in FRI layer at the
/// specified positions.
fn query_layer<E: FieldElement, H: Hasher, V: VectorCommitment<H>, const N: usize>(
    layer: &FriLayer<E, H, V>,
    positions: &[usize],
) -> FriProofLayer {
    // build a batch opening proof for all query positions
    let proof = layer
        .commitment
        .open_many(positions)
        .expect("failed to generate a batch opening proof for FRI layer queries");

    // build a list of polynomial evaluations at each position; since evaluations in FRI layers
    // are stored in transposed form, a position refers to N evaluations which are committed
    // in a single leaf
    let evaluations: &[[E; N]] = group_slice_elements(&layer.evaluations);
    let mut queried_values: Vec<[E; N]> = Vec::with_capacity(positions.len());
    for &position in positions.iter() {
        queried_values.push(evaluations[position]);
    }
    FriProofLayer::new::<_, _, V, N>(queried_values, proof.1)
}

/// Hashes each of the arrays in the provided slice and returns a vector commitment to resulting
/// hashes.
pub fn build_layer_commitment<E, H, V, const N: usize>(
    values: &[[E; N]],
) -> Result<V, <V as VectorCommitment<H>>::Error>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
    V: VectorCommitment<H>,
{
    let mut hashed_evaluations: Vec<H::Digest> = unsafe { uninit_vector(values.len()) };
    iter_mut!(hashed_evaluations, 1024).zip(values).for_each(|(e, v)| {
        let digest: H::Digest = H::hash_elements(v);
        *e = digest
    });

    V::new(hashed_evaluations)
}
