// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains an implementation of FRI verifier and associated components.

use alloc::vec::Vec;
use core::{marker::PhantomData, mem};

use crypto::{ElementHasher, RandomCoin, VectorCommitment};
use math::{polynom, FieldElement, StarkField};

use crate::{folding::fold_positions, utils::map_positions_to_indexes, FriOptions, VerifierError};

mod channel;
pub use channel::{DefaultVerifierChannel, VerifierChannel};

// FRI VERIFIER
// ================================================================================================
/// Implements the verifier component of the FRI protocol.
///
/// Given a small number of evaluations of some function *f* over domain *D* and a FRI proof, a
/// FRI verifier determines whether *f* is a polynomial of some bounded degree *d*, such that *d*
/// < |*D*| / 2.
///
/// The verifier is parametrized by the following types:
///
/// * `B` specifies the base field of the STARK protocol.
/// * `E` specifies the field in which the FRI protocol is executed. This can be the same as the
///   base field `B`, but it can also be an extension of the base field in cases when the base field
///   is too small to provide desired security level for the FRI protocol.
/// * `C` specifies the type used to simulate prover-verifier interaction. This type is used as an
///   abstraction for a [FriProof](crate::FriProof). Meaning, the verifier does not consume a FRI
///   proof directly, but reads it via [VerifierChannel] interface.
/// * `H` specifies the Hash function used by the prover to commit to polynomial evaluations.
///
/// Proof verification is performed in two phases: commit phase and query phase.
///
/// # Commit phase
/// During the commit phase, which is executed when the verifier is instantiated via
/// [new()](FriVerifier::new()) function, the verifier receives a list of FRI layer commitments
/// from the prover (via [VerifierChannel]). After each received commitment, the verifier
/// draws a random value α from the entire field, and sends it to the prover. In the
/// non-interactive version of the protocol, α values are derived pseudo-randomly from FRI
/// layer commitments.
///
/// # Query phase
/// During the query phase, which is executed via [verify()](FriVerifier::verify()) function,
/// the verifier sends a set of positions in the domain *D* to the prover, and the prover responds
/// with polynomial evaluations at these positions (together with corresponding opening proofs)
/// across all FRI layers. The verifier then checks that:
/// * The opening proofs are valid against the layer commitments the verifier received during the
///   commit phase.
/// * The evaluations are consistent across FRI layers (i.e., the degree-respecting projection was
///   applied correctly).
/// * The degree of the polynomial implied by evaluations at the last FRI layer (the remainder) is
///   smaller than the degree resulting from reducing degree *d* by `folding_factor` at each FRI
///   layer.
pub struct FriVerifier<E, C, H, R, V>
where
    E: FieldElement,
    C: VerifierChannel<E, Hasher = H>,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: E::BaseField,
    layer_commitments: Vec<H::Digest>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
    _channel: PhantomData<C>,
    _public_coin: PhantomData<R>,
    _vector_com: PhantomData<V>,
}

impl<E, C, H, R, V> FriVerifier<E, C, H, R, V>
where
    E: FieldElement,
    C: VerifierChannel<E, Hasher = H, VectorCommitment = V>,
    H: ElementHasher<BaseField = E::BaseField>,
    R: RandomCoin<BaseField = E::BaseField, Hasher = H>,
    V: VectorCommitment<H>,
{
    /// Returns a new instance of FRI verifier created from the specified parameters.
    ///
    /// The `max_poly_degree` parameter specifies the highest polynomial degree accepted by the
    /// returned verifier. In combination with `blowup_factor` from the `options` parameter,
    /// `max_poly_degree` also defines the domain over which the tested polynomial is evaluated.
    ///
    /// Creating a FRI verifier executes the commit phase of the FRI protocol from the verifier's
    /// perspective. Specifically, the verifier reads FRI layer commitments from the `channel`,
    /// and for each commitment, updates the `public_coin` with this commitment and then draws
    /// a random value α from the coin.
    ///
    /// The verifier stores layer commitments and corresponding α values in its internal state,
    /// and, thus, an instance of FRI verifier can be used to verify only a single proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// * `max_poly_degree` is inconsistent with the number of FRI layers read from the channel and
    ///   `folding_factor` specified in the `options` parameter.
    /// * An error was encountered while drawing a random α value from the coin.
    pub fn new(
        channel: &mut C,
        public_coin: &mut R,
        options: FriOptions,
        max_poly_degree: usize,
    ) -> Result<Self, VerifierError> {
        // infer evaluation domain info
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = E::BaseField::get_root_of_unity(domain_size.ilog2());

        let num_partitions = channel.read_fri_num_partitions();

        // read layer commitments from the channel and use them to build a list of alphas
        let layer_commitments = channel.read_fri_layer_commitments();
        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        let mut max_degree_plus_1 = max_poly_degree + 1;
        for (depth, commitment) in layer_commitments.iter().enumerate() {
            public_coin.reseed(*commitment);
            let alpha = public_coin.draw().map_err(VerifierError::RandomCoinError)?;
            layer_alphas.push(alpha);

            // make sure the degree can be reduced by the folding factor at all layers
            // but the remainder layer
            if depth != layer_commitments.len() - 1
                && max_degree_plus_1 % options.folding_factor() != 0
            {
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    options.folding_factor(),
                    depth,
                ));
            }
            max_degree_plus_1 /= options.folding_factor();
        }

        Ok(FriVerifier {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            num_partitions,
            _channel: PhantomData,
            _public_coin: PhantomData,
            _vector_com: PhantomData,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns maximum degree of a polynomial accepted by this verifier.
    pub fn max_poly_degree(&self) -> usize {
        self.max_poly_degree
    }

    /// Returns size of the domain over which a polynomial commitment checked by this verifier
    /// has been evaluated.
    ///
    /// The domain size can be computed by rounding `max_poly_degree` to the next power of two
    /// and multiplying the result by the `blowup_factor` from the protocol options.
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// Returns number of partitions used during FRI proof generation.
    ///
    /// For non-distributed proof generation, number of partitions is usually set to 1.
    pub fn num_partitions(&self) -> usize {
        self.num_partitions
    }

    /// Returns protocol configuration options for this verifier.
    pub fn options(&self) -> &FriOptions {
        &self.options
    }

    // VERIFICATION PROCEDURE
    // --------------------------------------------------------------------------------------------
    /// Executes the query phase of the FRI protocol.
    ///
    /// Returns `Ok(())` if values in the `evaluations` slice represent evaluations of a polynomial
    /// with degree <= `max_poly_degree` at x coordinates specified by the `positions` slice.
    ///
    /// Thus, `positions` parameter represents the positions in the evaluation domain at which the
    /// verifier queries the prover at the first FRI layer. Similarly, the `evaluations` parameter
    /// specifies the evaluations of the polynomial at the first FRI layer returned by the prover
    /// for these positions.
    ///
    /// Evaluations of layer polynomials for all subsequent FRI layers the verifier reads from the
    /// specified `channel`.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The length of `evaluations` is not equal to the length of `positions`.
    /// * An unsupported folding factor was specified by the `options` for this verifier.
    /// * Decommitments to polynomial evaluations don't match the commitment value at any of the FRI
    ///   layers.
    /// * The verifier detects an error in how the degree-respecting projection was applied at any
    ///   of the FRI layers.
    /// * The degree of the remainder at the last FRI layer is greater than the degree implied by
    ///   `max_poly_degree` reduced by the folding factor at each FRI layer.
    pub fn verify(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        if evaluations.len() != positions.len() {
            return Err(VerifierError::NumPositionEvaluationMismatch(
                positions.len(),
                evaluations.len(),
            ));
        }

        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
        match folding_factor {
            2 => self.verify_generic::<2>(channel, evaluations, positions),
            4 => self.verify_generic::<4>(channel, evaluations, positions),
            8 => self.verify_generic::<8>(channel, evaluations, positions),
            16 => self.verify_generic::<16>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    /// This is the actual implementation of the verification procedure described above, but it
    /// also takes folding factor as a generic parameter N.
    fn verify_generic<const N: usize>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| self.domain_generator.exp_vartime(((self.domain_size / N * i) as u64).into()))
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -------------------------------
        let mut domain_generator = self.domain_generator;
        let mut domain_size = self.domain_size;
        let mut max_degree_plus_1 = self.max_poly_degree + 1;
        let mut positions = positions.to_vec();
        let mut evaluations = evaluations.to_vec();

        for depth in 0..self.options.num_fri_layers(self.domain_size) {
            // determine which evaluations were queried in the folded layer
            let mut folded_positions =
                fold_positions(&positions, domain_size, self.options.folding_factor());
            // determine where these evaluations are in the vector commitment
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                self.options.folding_factor(),
                self.num_partitions,
            );
            // read query values from the specified indexes
            let layer_commitment = self.layer_commitments[depth];
            // TODO: add layer depth to the potential error message
            let layer_values = channel.read_layer_queries(&position_indexes, &layer_commitment)?;
            let query_values =
                get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
            if evaluations != query_values {
                return Err(VerifierError::InvalidLayerFolding(depth));
            }

            // build a set of x coordinates for each row polynomial
            #[rustfmt::skip]
            let xs = folded_positions.iter().map(|&i| {
                let xe = domain_generator.exp_vartime((i as u64).into()) * self.options.domain_offset();
                folding_roots.iter()
                    .map(|&r| E::from(xe * r))
                    .collect::<Vec<_>>().try_into().unwrap()
            })
            .collect::<Vec<_>>();

            // interpolate x and y values into row polynomials
            let row_polys = polynom::interpolate_batch(&xs, &layer_values);

            // calculate the pseudo-random value used for linear combination in layer folding
            let alpha = self.layer_alphas[depth];

            // check that when the polynomials are evaluated at alpha, the result is equal to
            // the corresponding column value
            evaluations = row_polys.iter().map(|p| polynom::eval(p, alpha)).collect();

            // make sure next degree reduction does not result in degree truncation
            if max_degree_plus_1 % N != 0 {
                return Err(VerifierError::DegreeTruncation(max_degree_plus_1 - 1, N, depth));
            }

            // update variables for the next iteration of the loop
            domain_generator = domain_generator.exp_vartime((N as u32).into());
            max_degree_plus_1 /= N;
            domain_size /= N;
            mem::swap(&mut positions, &mut folded_positions);
        }

        // 2 ----- verify the remainder polynomial of the FRI proof -------------------------------

        // read the remainder polynomial from the channel and make sure it agrees with the
        // evaluations from the previous layer.
        // note that the coefficients of the remainder polynomial are sent in reverse order and
        // this simplifies evaluation using Horner's method.
        let remainder_poly = channel.read_remainder()?;
        if remainder_poly.len() > max_degree_plus_1 {
            return Err(VerifierError::RemainderDegreeMismatch(max_degree_plus_1 - 1));
        }
        let offset: E::BaseField = self.options().domain_offset();

        for (&position, evaluation) in positions.iter().zip(evaluations) {
            let comp_eval = eval_horner_rev::<E>(
                &remainder_poly,
                offset * domain_generator.exp_vartime((position as u64).into()),
            );
            if comp_eval != evaluation {
                return Err(VerifierError::InvalidRemainderFolding);
            }
        }

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn get_query_values<E: FieldElement, const N: usize>(
    values: &[[E; N]],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
) -> Vec<E> {
    let row_length = domain_size / N;

    let mut result = Vec::new();
    for position in positions {
        let idx = folded_positions.iter().position(|&v| v == position % row_length).unwrap();
        let value = values[idx][position / row_length];
        result.push(value);
    }

    result
}

/// Evaluates a polynomial with coefficients in an extension field given in reverse order at a point
/// in the base field.
fn eval_horner_rev<E>(p: &[E], x: E::BaseField) -> E
where
    E: FieldElement,
{
    p.iter().fold(E::ZERO, |acc, &coeff| acc * E::from(x) + coeff)
}
