// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{Air, CompositionCoefficients, ConstraintDivisor, EvaluationFrame, PublicCoin};
use math::{
    field::{FieldElement, StarkField},
    polynom,
};

// CONSTRAINT EVALUATION
// ================================================================================================

/// Evaluates constraints for the specified evaluation frame.
pub fn evaluate_constraints<A: Air, C: PublicCoin, E: FieldElement + From<A::BaseElement>>(
    air: &A,
    coin: &C,
    ood_frame: &EvaluationFrame<E>,
    x: E,
) -> E {
    // ----- evaluate transition constraints ------------------------------------------------------

    // initialize a buffer to hold transition constraint evaluations
    let mut t_evaluations = E::zeroed_vector(air.num_transition_constraints());

    // compute values of periodic columns at x
    let periodic_values = air
        .get_periodic_column_polys()
        .iter()
        .map(|poly| {
            let num_cycles = air.trace_length() / poly.len();
            let x = x.exp((num_cycles as u32).into());
            polynom::eval(poly, x)
        })
        .collect::<Vec<_>>();

    // evaluate transition constraints over OOD evaluation frame
    air.evaluate_transition(ood_frame, &periodic_values, &mut t_evaluations);

    // merge all constraint evaluations into a single value by computing their random linear
    // combination using coefficients drawn from the public coin
    let t_constraints = air.get_transition_constraints(coin.get_transition_coefficient_prng());
    let t_evaluation = t_constraints.iter().fold(E::ZERO, |acc, group| {
        acc + group.merge_evaluations(&t_evaluations, x)
    });

    // build the divisor for transition constraints; divisors for all transition constraints are
    // the same and have the form: (x^steps - 1) / (x - x_at_last_step)
    let t_divisor = ConstraintDivisor::<A::BaseElement>::from_transition(air.context());

    // divide out the evaluation of divisor at x
    let z = t_divisor.evaluate_at(x);
    let mut result = t_evaluation / z;

    // ----- evaluate boundary constraints --------------------------------------------------------

    // get boundary constraints grouped by common divisor from the AIR
    let b_constraints = air.get_boundary_constraints(coin.get_boundary_coefficient_prng());

    // iterate over boundary constraint groups (each group has a distinct divisor), evaluate
    // constraints in each group and add them to the evaluations vector

    // cache power of x here so that we only re-compute it when degree_adjustment changes
    let mut degree_adjustment = b_constraints[0].degree_adjustment();
    let mut xp = x.exp(degree_adjustment.into());

    for group in b_constraints.iter() {
        // if adjustment degree hasn't changed, no need to recompute `xp` - so just reuse the
        // previous value; otherwise, compute new `xp`
        if group.degree_adjustment() != degree_adjustment {
            degree_adjustment = group.degree_adjustment();
            xp = x.exp(degree_adjustment.into());
        }
        // evaluate all constraints in the group, and the divide out the value implied
        // by the divisor
        let evaluation = group.evaluate_at(&ood_frame.current, x, xp);
        let z = group.divisor().evaluate_at(x);
        result += evaluation / z;
    }

    result
}

// CONSTRAINT COMPOSITION
// ================================================================================================

/// TODO: add comments
pub fn compose_constraints<B: StarkField, E: FieldElement + From<B>>(
    evaluation_queries: &[Vec<E>],
    x_coordinates: &[B],
    z: E,
    ood_constraint_evaluations: &[E],
    cc: &CompositionCoefficients<E>,
) -> Vec<E> {
    let mut result = Vec::with_capacity(evaluation_queries.len());

    let num_evaluation_columns = ood_constraint_evaluations.len() as u32;
    let z = z.exp(num_evaluation_columns.into());

    for (query_values, &x) in evaluation_queries.iter().zip(x_coordinates) {
        let mut row_value = E::ZERO;
        for (i, &evaluation) in query_values.iter().enumerate() {
            // compute C(x) = (P(x) - P(z)) / (x - z)
            let composition = (evaluation - ood_constraint_evaluations[i]) / (E::from(x) - z);
            // multiply by pseudo-random coefficient for linear combination
            row_value += composition * cc.constraints[i];
        }
        result.push(row_value);
    }

    result
}
