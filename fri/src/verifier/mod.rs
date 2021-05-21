// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{folding::quartic, utils, VerifierError};
use math::{
    field::{FieldElement, StarkField},
    polynom,
    utils::get_power_series_with_offset,
};
use std::mem;

mod context;
pub use context::VerifierContext;

mod channel;
pub use channel::{DefaultVerifierChannel, VerifierChannel};

// VERIFICATION PROCEDURE
// ================================================================================================

/// Returns OK(()) if values in the `evaluations` slice represent evaluations of a polynomial
/// with degree <= context.max_degree() at x coordinates specified by the `positions` slice. The
/// evaluation domain is defined by the combination of base field (specified by B type parameter)
/// and context.domain_size() parameter.
pub fn verify<B, E, C>(
    context: &VerifierContext<B, E>,
    channel: &C,
    evaluations: &[E],
    positions: &[usize],
) -> Result<(), VerifierError>
where
    B: StarkField,
    E: FieldElement + From<B>,
    C: VerifierChannel<E>,
{
    assert_eq!(
        evaluations.len(),
        positions.len(),
        "number of positions must match the number of evaluations"
    );
    let domain_size = context.domain_size();
    let domain_generator = context.domain_generator();
    let domain_offset = context.domain_offset();
    let num_partitions = channel.num_fri_partitions();

    // powers of the given root of unity 1, p, p^2, p^3 such that p^4 = 1
    let quartic_roots = [
        B::ONE,
        domain_generator.exp((domain_size as u32 / 4).into()),
        domain_generator.exp((domain_size as u32 / 2).into()),
        domain_generator.exp((domain_size as u32 * 3 / 4).into()),
    ];

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
        let layer_values = channel.read_layer_queries(depth, &position_indexes)?;
        let query_values = get_query_values(
            &layer_values,
            &positions,
            &folded_positions,
            domain_size,
            context.folding_factor(),
        );
        if evaluations != query_values {
            return Err(VerifierError::LayerValuesNotConsistent(depth));
        }

        // build a set of x for each row polynomial
        let mut xs = Vec::with_capacity(folded_positions.len());
        for &i in folded_positions.iter() {
            let xe = domain_generator.exp((i as u32).into()) * domain_offset;
            xs.push([
                quartic_roots[0] * xe,
                quartic_roots[1] * xe,
                quartic_roots[2] * xe,
                quartic_roots[3] * xe,
            ]);
        }

        // interpolate x and y values into row polynomials
        let row_polys = quartic::interpolate_batch(&xs, &layer_values);

        // calculate the pseudo-random value used for linear combination in layer folding
        let alpha = context.alphas()[depth];

        // check that when the polynomials are evaluated at alpha, the result is equal to
        // the corresponding column value
        evaluations = quartic::evaluate_batch(&row_polys, alpha);

        // update variables for the next iteration of the loop
        domain_generator = domain_generator.exp(4u32.into());
        max_degree_plus_1 /= 4;
        domain_size /= 4;
        mem::swap(&mut positions, &mut folded_positions);
    }

    // 2 ----- verify the remainder of the FRI proof ----------------------------------------------

    // read the remainder from the channel and make sure it matches with the columns
    // of the previous layer
    let remainder = channel.read_remainder()?;
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

/// Returns Ok(true) if values in the `remainder` slice represent evaluations of a polynomial
/// with degree < max_degree_plus_1 against a domain specified by the `domain_generator`.
fn verify_remainder<B, E>(
    remainder: Vec<E>,
    max_degree_plus_1: usize,
    domain_generator: B,
    blowup_factor: usize,
) -> Result<(), VerifierError>
where
    B: StarkField,
    E: FieldElement + From<B>,
{
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
fn get_query_values<E: FieldElement>(
    values: &[[E; 4]],
    positions: &[usize],
    folded_positions: &[usize],
    domain_size: usize,
    folding_factor: usize,
) -> Vec<E> {
    let row_length = domain_size / folding_factor;

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
