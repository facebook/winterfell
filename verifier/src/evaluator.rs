// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{
    Air, AuxRandElements, ConstraintCompositionCoefficients, EvaluationFrame,
    LagrangeKernelEvaluationFrame, LogUpGkrEvaluator,
};
use math::{polynom, FieldElement};

// CONSTRAINT EVALUATION
// ================================================================================================

/// Evaluates constraints for the specified evaluation frame.
pub fn evaluate_constraints<A: Air, E: FieldElement<BaseField = A::BaseField>>(
    air: &A,
    composition_coefficients: ConstraintCompositionCoefficients<E>,
    main_trace_frame: &EvaluationFrame<E>,
    aux_trace_frame: &Option<EvaluationFrame<E>>,
    lagrange_kernel_frame: Option<&LagrangeKernelEvaluationFrame<E>>,
    aux_rand_elements: Option<&AuxRandElements<E>>,
    x: E,
) -> E {
    // 1 ----- evaluate transition constraints ----------------------------------------------------

    // initialize a buffer to hold transition constraint evaluations
    let t_constraints = air.get_transition_constraints(&composition_coefficients.transition);

    // compute values of periodic columns at x
    let periodic_values = air
        .get_periodic_column_polys()
        .iter()
        .map(|poly| {
            let num_cycles = air.trace_length() / poly.len();
            let x = x.exp_vartime((num_cycles as u32).into());
            polynom::eval(poly, x)
        })
        .collect::<Vec<_>>();

    // evaluate transition constraints for the main trace segment
    let mut t_evaluations1 = vec![E::ZERO; t_constraints.num_main_constraints()];
    air.evaluate_transition(main_trace_frame, &periodic_values, &mut t_evaluations1);

    // evaluate transition constraints for the auxiliary trace segment (if any)
    let mut t_evaluations2 = vec![E::ZERO; t_constraints.num_aux_constraints()];
    if let Some(aux_trace_frame) = aux_trace_frame {
        let aux_rand_elements =
            aux_rand_elements.expect("expected aux rand elements to be present");

        air.evaluate_aux_transition(
            main_trace_frame,
            aux_trace_frame,
            &periodic_values,
            aux_rand_elements,
            &mut t_evaluations2,
        );
    }

    // merge all constraint evaluations into a single value by computing their random linear
    // combination using coefficients drawn from the public coin. this also divides the result
    // by the divisor of transition constraints.
    let mut result = t_constraints.combine_evaluations::<E>(&t_evaluations1, &t_evaluations2, x);

    // 2 ----- evaluate boundary constraints ------------------------------------------------------

    // get boundary constraints grouped by common divisor from the AIR
    let b_constraints =
        air.get_boundary_constraints(aux_rand_elements, &composition_coefficients.boundary);

    // iterate over boundary constraint groups for the main trace segment (each group has a
    // distinct divisor), evaluate constraints in each group and add their combination to the
    // result
    for group in b_constraints.main_constraints().iter() {
        result += group.evaluate_at(main_trace_frame.current(), x);
    }

    // iterate over boundary constraint groups for the auxiliary trace segment (each group has a
    // distinct divisor), evaluate constraints in each group and add their combination to the
    // result
    if let Some(aux_trace_frame) = aux_trace_frame {
        for group in b_constraints.aux_constraints().iter() {
            result += group.evaluate_at(aux_trace_frame.current(), x);
        }
    }

    // 3 ----- evaluate Lagrange kernel constraints ------------------------------------

    if let Some(lagrange_kernel_column_frame) = lagrange_kernel_frame {
        let logup_gkr_evaluator = air.get_logup_gkr_evaluator();

        let lagrange_coefficients = composition_coefficients
            .lagrange
            .expect("expected Lagrange kernel composition coefficients to be present");

        let gkr_data = aux_rand_elements
            .expect("expected aux rand elements to be present")
            .gkr_data()
            .expect("expected LogUp-GKR rand elements to be present");

        // Lagrange kernel constraints

        let lagrange_constraints = logup_gkr_evaluator.get_lagrange_kernel_constraints(
            lagrange_coefficients,
            &gkr_data.lagrange_kernel_eval_point,
        );

        result += lagrange_constraints.transition.evaluate_and_combine::<E>(
            lagrange_kernel_column_frame,
            &gkr_data.lagrange_kernel_eval_point,
            x,
        );
        result += lagrange_constraints.boundary.evaluate_at(x, lagrange_kernel_column_frame);

        // s-column constraints

        let s_col_idx = air.trace_info().s_column_idx().expect("s-column should be present");

        let aux_trace_frame =
            aux_trace_frame.as_ref().expect("expected aux rand elements to be present");

        let s_cur = aux_trace_frame.current()[s_col_idx];
        let s_nxt = aux_trace_frame.next()[s_col_idx];
        let l_cur = lagrange_kernel_column_frame.inner()[0];

        let s_column_cc = composition_coefficients
            .s_col
            .expect("expected constraint composition coefficient for s-column to be present");

        let s_column_constraint =
            logup_gkr_evaluator.get_s_column_constraints(gkr_data, s_column_cc);

        result += s_column_constraint.evaluate(air, main_trace_frame, s_cur, s_nxt, l_cur, x);
    }

    result
}
