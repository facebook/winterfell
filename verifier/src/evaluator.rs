// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{Air, ConstraintCompositionCoefficients, EvaluationFrame};
use math::{polynom, FieldElement};
use utils::collections::Vec;

// CONSTRAINT EVALUATION
// ================================================================================================

/// Evaluates constraints for the specified evaluation frame.
pub fn evaluate_constraints<A: Air, E: FieldElement<BaseField = A::BaseField>>(
    air: &A,
    coefficients: ConstraintCompositionCoefficients<E>,
    ood_frame: &EvaluationFrame<E>,
    x: E,
) -> E {
    // 1 ----- evaluate transition constraints ----------------------------------------------------

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
    let t_constraints = air.get_transition_constraints(&coefficients.transition);
    let t_evaluation = t_constraints.iter().fold(E::ZERO, |acc, group| {
        acc + group.merge_evaluations(&t_evaluations, x)
    });

    // divide out the evaluation of divisor at x
    let z = air.transition_constraint_divisor().evaluate_at(x);
    let mut result = t_evaluation / z;

    // 2 ----- evaluate boundary constraints ------------------------------------------------------

    // get boundary constraints grouped by common divisor from the AIR
    let b_constraints = air.get_boundary_constraints(&coefficients.boundary);

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
        // evaluate all constraints in the group, and add the evaluation to the result
        result += group.evaluate_at(ood_frame.current(), x, xp);
    }

    result
}
