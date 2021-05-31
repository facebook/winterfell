// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{utils, VerifierError};
use crypto::Hasher;
use math::{
    field::{FieldElement, StarkField},
    polynom,
    utils::get_power_series_with_offset,
};
use std::{convert::TryInto, mem};

mod context;
pub use context::VerifierContext;

mod channel;
pub use channel::{DefaultVerifierChannel, VerifierChannel};

// VERIFICATION PROCEDURE
// ================================================================================================
/// Returns OK(()) if values in the `evaluations` slice represent evaluations of a polynomial
/// with degree <= context.max_degree() at x coordinates specified by the `positions` slice. The
/// evaluation domain is defined by the combination of base field (specified by B type parameter),
/// context.domain_size() parameter, and context.domain_offset() parameter.
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
    match context.folding_factor() {
        4 => verify_generic::<B, E, H, C, 4>(context, channel, evaluations, positions),
        8 => verify_generic::<B, E, H, C, 8>(context, channel, evaluations, positions),
        16 => verify_generic::<B, E, H, C, 16>(context, channel, evaluations, positions),
        _ => unimplemented!(
            "folding factor {} is not supported",
            context.folding_factor()
        ),
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
    assert_eq!(
        evaluations.len(),
        positions.len(),
        "number of positions must match the number of evaluations"
    );
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
    let mut max_degree_plus_1 = context.max_degree() + 1;
    let mut positions = positions.to_vec();
    let mut evaluations = evaluations.to_vec();

    for depth in 0..context.num_fri_layers() {
        // determine which evaluations were queried in the folded layer
        let mut folded_positions =
            utils::fold_positions(&positions, domain_size, context.folding_factor());
        // determine where these evaluations are in the commitment Merkle tree
        let position_indexes = utils::map_positions_to_indexes(
            &folded_positions,
            domain_size,
            context.folding_factor(),
            num_partitions,
        );
        // read query values from the specified indexes in the Merkle tree
        let layer_commitment = context.layer_commitments()[depth];
        let layer_values =
            channel.read_layer_queries(depth, &position_indexes, &layer_commitment)?;
        let query_values =
            get_query_values::<E, N>(&layer_values, &positions, &folded_positions, domain_size);
        if evaluations != query_values {
            return Err(VerifierError::LayerValuesNotConsistent(depth));
        }

        // build a set of x for each row polynomial
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
    let remainder = channel.read_remainder(&remainder_commitment)?;
    for (&position, evaluation) in positions.iter().zip(evaluations) {
        if remainder[position] != evaluation {
            return Err(VerifierError::RemainderValuesNotConsistent);
        }
    }

    // make sure the remainder values satisfy the degree
    verify_remainder(
        remainder,
        max_degree_plus_1,
        domain_generator,
        context.blowup_factor(),
    )
}

// REMAINDER DEGREE VERIFICATION
// ================================================================================================
/// Returns Ok(true) if values in the `remainder` slice represent evaluations of a polynomial
/// with degree < max_degree_plus_1 against a domain specified by the `domain_generator`.
fn verify_remainder<B: StarkField, E: FieldElement<BaseField = B>>(
    remainder: Vec<E>,
    max_degree_plus_1: usize,
    domain_generator: B,
    blowup_factor: usize,
) -> Result<(), VerifierError> {
    if max_degree_plus_1 > remainder.len() {
        return Err(VerifierError::RemainderDegreeNotValid);
    }

    // exclude points which should be skipped during evaluation
    let mut positions = Vec::new();
    for i in 0..remainder.len() {
        if i % blowup_factor != 0 {
            positions.push(i);
        }
    }

    // pick a subset of points from the remainder and interpolate them into a polynomial
    let domain = get_power_series_with_offset(domain_generator, B::GENERATOR, remainder.len());
    let mut xs = Vec::with_capacity(max_degree_plus_1);
    let mut ys = Vec::with_capacity(max_degree_plus_1);
    for &p in positions.iter().take(max_degree_plus_1) {
        xs.push(E::from(domain[p]));
        ys.push(remainder[p]);
    }
    let poly = polynom::interpolate(&xs, &ys, false);

    // check that polynomial evaluates correctly for all other points in the remainder
    for &p in positions.iter().skip(max_degree_plus_1) {
        if polynom::eval(&poly, E::from(domain[p])) != remainder[p] {
            return Err(VerifierError::RemainderDegreeMismatch(
                max_degree_plus_1 - 1,
            ));
        }
    }
    Ok(())
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
