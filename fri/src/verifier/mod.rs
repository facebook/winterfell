// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains an implementation of FRI verifier and associated components.

use crate::{folding::fold_positions, utils::map_positions_to_indexes, FriOptions, VerifierError};
use crypto::{Hasher, RandomCoin};
use math::{fft, log2, polynom, FieldElement, StarkField};
use std::{convert::TryInto, mem};

mod channel;
pub use channel::{DefaultVerifierChannel, VerifierChannel};

// FRI VERIFIER
// ================================================================================================
/// Implements the verifier component of the FRI protocol.
///
/// The verifier is parametrized by the following types:
///
/// * `B` specifies the base field of the STARK protocol.
/// * `E` specifies the filed in which the FRI protocol is executed. This can be the same as the
///   base field `B`, but it can also be an extension of the base field in cases when the base
///   field is too small to provide desired security level for the FRI protocol.
/// * `H` specifies the Hash function used by the prover to commit to polynomial evaluations.
///
/// These properties include:
/// * A set of parameters for the protocol such as `folding_factor` and `blowup_factor`
///   (specified via [FriOptions] parameter) as well as the number of partitions used during
///   proof generation (specified via `num_partitions` parameter).
/// * Maximum degree of a polynomial accepted by this instantiation of FRI (specified via
///   `max_poly_degree` parameter). In combination with `blowup_factor` parameter, this also
///   defines the domain over which the tested polynomial is evaluated.
/// * Information exchanged between the prover and the verifier during the commit phase of
///   the FRI protocol. This includes `layer_commitments` sent from the prover to the
///   verifier, and `layer_alphas` sent from the verifier to the prover.
pub struct FriVerifier<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> {
    max_poly_degree: usize,
    domain_size: usize,
    domain_generator: B,
    layer_commitments: Vec<H::Digest>,
    layer_alphas: Vec<E>,
    options: FriOptions,
    num_partitions: usize,
}

impl<B: StarkField, E: FieldElement<BaseField = B>, H: Hasher> FriVerifier<B, E, H> {
    /// Returns a new instance of FRI verifier created from the specified parameters.
    pub fn new(
        max_poly_degree: usize,
        layer_commitments: Vec<H::Digest>,
        public_coin: &mut RandomCoin<B, H>,
        num_partitions: usize,
        options: FriOptions,
    ) -> Result<Self, VerifierError> {
        let domain_size = max_poly_degree.next_power_of_two() * options.blowup_factor();
        let domain_generator = B::get_root_of_unity(log2(domain_size));

        let mut layer_alphas = Vec::with_capacity(layer_commitments.len());
        for commitment in layer_commitments.iter() {
            public_coin.reseed(*commitment);
            let alpha = public_coin
                .draw()
                .map_err(|_| VerifierError::PublicCoinError)?;
            layer_alphas.push(alpha);
        }

        Ok(FriVerifier {
            max_poly_degree,
            domain_size,
            domain_generator,
            layer_commitments,
            layer_alphas,
            options,
            num_partitions,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns maximum degree of a polynomial accepted by this FRI verifier.
    pub fn max_poly_degree(&self) -> usize {
        self.max_poly_degree
    }

    /// Returns size of the domain over which a polynomial commitment checked by this FRI verifier
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

    /// Returns protocol configuration options for this FRI verifier.
    pub fn options(&self) -> &FriOptions {
        &self.options
    }

    // VERIFICATION PROCEDURE
    // --------------------------------------------------------------------------------------------
    /// Verifies a FRI proof read from the specified channel.
    ///
    /// Returns OK(()) if values in the `evaluations` slice represent evaluations of a polynomial
    /// with degree <= `context.max_degree()` at x coordinates specified by the `positions` slice. The
    /// evaluation domain is defined by the combination of base field (specified by B type parameter),
    /// context.domain_size() parameter, and context.domain_offset() parameter.
    ///
    /// # Errors
    /// Returns an error if:
    ///
    pub fn verify<C: VerifierChannel<E, Hasher = H>>(
        &self,
        channel: &mut C,
        evaluations: &[E],
        positions: &[usize],
    ) -> Result<(), VerifierError> {
        // static dispatch for folding factor parameter
        let folding_factor = self.options.folding_factor();
        match folding_factor {
            4 => self.verify_generic::<C, 4>(channel, evaluations, positions),
            8 => self.verify_generic::<C, 8>(channel, evaluations, positions),
            16 => self.verify_generic::<C, 16>(channel, evaluations, positions),
            _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
        }
    }

    /// This is the actual implementation of the verification procedure described above, but it
    /// also takes folding factor as a generic parameter N.
    fn verify_generic<C: VerifierChannel<E, Hasher = H>, const N: usize>(
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

        // pre-compute roots of unity used in computing x coordinates in the folded domain
        let folding_roots = (0..N)
            .map(|i| {
                self.domain_generator
                    .exp(((self.domain_size / N * i) as u64).into())
            })
            .collect::<Vec<_>>();

        // 1 ----- verify the recursive components of the FRI proof -----------------------------------
        let mut domain_generator = self.domain_generator;
        let mut domain_size = self.domain_size;
        let mut max_degree_plus_1 = self.max_poly_degree + 1;
        let mut positions = positions.to_vec();
        let mut evaluations = evaluations.to_vec();

        for depth in 0..self.options.num_fri_layers(self.domain_size) {
            // determine which evaluations were queried in the folded layer
            let mut folded_positions =
                fold_positions(&positions, domain_size, self.options.folding_factor());
            // determine where these evaluations are in the commitment Merkle tree
            let position_indexes = map_positions_to_indexes(
                &folded_positions,
                domain_size,
                self.options.folding_factor(),
                self.num_partitions,
            );
            // read query values from the specified indexes in the Merkle tree
            let layer_commitment = self.layer_commitments[depth];
            // TODO: add layer depth to the potential error message
            let layer_values = channel.read_layer_queries(&position_indexes, &layer_commitment)?;
            let query_values =
                get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
            if evaluations != query_values {
                return Err(VerifierError::LayerValuesNotConsistent(depth));
            }

            // build a set of x coordinates for each row polynomial
            #[rustfmt::skip]
            let xs = folded_positions.iter().map(|&i| {
                let xe = domain_generator.exp((i as u64).into()) * self.options.domain_offset();
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
                return Err(VerifierError::DegreeTruncation(
                    max_degree_plus_1 - 1,
                    N,
                    depth,
                ));
            }

            // update variables for the next iteration of the loop
            domain_generator = domain_generator.exp((N as u32).into());
            max_degree_plus_1 /= N;
            domain_size /= N;
            mem::swap(&mut positions, &mut folded_positions);
        }

        // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

        // read the remainder from the channel and make sure it matches with the columns
        // of the previous layer
        let remainder_commitment = self.layer_commitments.last().unwrap();
        let remainder = channel.read_remainder::<N>(remainder_commitment)?;
        for (&position, evaluation) in positions.iter().zip(evaluations) {
            if remainder[position] != evaluation {
                return Err(VerifierError::RemainderValuesNotConsistent);
            }
        }

        // make sure the remainder values satisfy the degree
        verify_remainder(remainder, max_degree_plus_1 - 1)
    }
}

// REMAINDER DEGREE VERIFICATION
// ================================================================================================
/// Returns Ok(true) if values in the `remainder` slice represent evaluations of a polynomial
/// with degree < max_degree_plus_1 against a domain specified by the `domain_generator` and
/// `domain_offset`.
fn verify_remainder<B: StarkField, E: FieldElement<BaseField = B>>(
    mut remainder: Vec<E>,
    max_degree: usize,
) -> Result<(), VerifierError> {
    if max_degree + 1 >= remainder.len() {
        return Err(VerifierError::RemainderDegreeNotValid);
    }

    let inv_twiddles = fft::get_inv_twiddles(remainder.len());
    fft::interpolate_poly(&mut remainder, &inv_twiddles);
    let poly = remainder;

    if max_degree < polynom::degree_of(&poly) {
        Err(VerifierError::RemainderDegreeMismatch(max_degree))
    } else {
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
        let idx = folded_positions
            .iter()
            .position(|&v| v == position % row_length)
            .unwrap();
        let value = values[idx][position / row_length];
        result.push(value);
    }

    result
}
