// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains an implementation of FRI verifier and associated components.

use crate::{folding::fold_positions, utils::map_positions_to_indexes, VerifierError};
use crypto::Hasher;
use math::{fft, polynom, FieldElement, StarkField};
use std::{convert::TryInto, mem};

mod context;
pub use context::VerifierContext;

mod channel;
pub use channel::{DefaultVerifierChannel, VerifierChannel};

// VERIFICATION PROCEDURE
// ================================================================================================
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
pub fn verify<B, E, H, C>(
    context: &VerifierContext<B, E, H>,
    channel: &mut C,
    evaluations: &[E],
    positions: &[usize],
) -> Result<(), VerifierError>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: Hasher,
    C: VerifierChannel<E, Hasher = H>,
{
    // static dispatch for folding factor parameter
    let folding_factor = context.folding_factor();
    match folding_factor {
        4 => verify_generic::<B, E, H, C, 4>(context, channel, evaluations, positions),
        8 => verify_generic::<B, E, H, C, 8>(context, channel, evaluations, positions),
        16 => verify_generic::<B, E, H, C, 16>(context, channel, evaluations, positions),
        _ => Err(VerifierError::UnsupportedFoldingFactor(folding_factor)),
    }
}

// GENERIC VERIFICATION
// ================================================================================================
/// This is the actual implementation of the verification procedure described above, but it also
/// takes folding factor as a generic parameter N.
fn verify_generic<B, E, H, C, const N: usize>(
    context: &VerifierContext<B, E, H>,
    channel: &mut C,
    evaluations: &[E],
    positions: &[usize],
) -> Result<(), VerifierError>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: Hasher,
    C: VerifierChannel<E, Hasher = H>,
{
    if evaluations.len() != positions.len() {
        return Err(VerifierError::NumPositionEvaluationMismatch(
            positions.len(),
            evaluations.len(),
        ));
    }
    let domain_size = context.domain_size();
    let domain_generator = context.domain_generator();
    let domain_offset = context.domain_offset();
    let num_partitions = context.num_partitions();

    // pre-compute roots of unity used in computing x coordinates in the folded domain
    let folding_roots = (0..N)
        .map(|i| domain_generator.exp(((domain_size / N * i) as u64).into()))
        .collect::<Vec<_>>();

    // 1 ----- verify the recursive components of the FRI proof -----------------------------------
    let mut domain_generator = domain_generator;
    let mut domain_size = domain_size;
    let mut max_degree_plus_1 = context.max_poly_degree() + 1;
    let mut positions = positions.to_vec();
    let mut evaluations = evaluations.to_vec();

    for depth in 0..context.num_fri_layers() {
        // determine which evaluations were queried in the folded layer
        let mut folded_positions =
            fold_positions(&positions, domain_size, context.folding_factor());
        // determine where these evaluations are in the commitment Merkle tree
        let position_indexes = map_positions_to_indexes(
            &folded_positions,
            domain_size,
            context.folding_factor(),
            num_partitions,
        );
        // read query values from the specified indexes in the Merkle tree
        let layer_commitment = context.layer_commitments()[depth];
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
            let xe = domain_generator.exp((i as u64).into()) * domain_offset;
            folding_roots.iter()
                .map(|&r| E::from(xe * r))
                .collect::<Vec<_>>().try_into().unwrap()
        })
        .collect::<Vec<_>>();

        // interpolate x and y values into row polynomials
        let row_polys = polynom::interpolate_batch(&xs, &layer_values);

        // calculate the pseudo-random value used for linear combination in layer folding
        let alpha = context.layer_alphas()[depth];

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
    let remainder_commitment = context.layer_commitments().last().unwrap();
    let remainder = channel.read_remainder::<N>(remainder_commitment)?;
    for (&position, evaluation) in positions.iter().zip(evaluations) {
        if remainder[position] != evaluation {
            return Err(VerifierError::RemainderValuesNotConsistent);
        }
    }

    // make sure the remainder values satisfy the degree
    verify_remainder(remainder, max_degree_plus_1 - 1)
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
