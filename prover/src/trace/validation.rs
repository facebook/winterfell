// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::TraceTable;
use air::{Air, EvaluationFrame};
use math::StarkField;

// TRACE VALIDATION
// ================================================================================================

/// Checks if an execution trace is valid against the specified AIR, and panics if not.
///
/// NOTE: this is a very expensive operation and is intended for use only in debug mode.
pub fn validate_trace<A: Air<BaseField = B>, B: StarkField>(trace: &TraceTable<B>, air: &A) {
    // TODO: eventually, this should return errors instead of panicking

    // make sure the width align; if they don't something went terribly wrong
    assert_eq!(
        trace.width(),
        air.trace_width(),
        "inconsistent trace width: expected {}, but was {}",
        trace.width(),
        air.trace_width()
    );

    // --- 1. make sure the assertions are valid --------------------------------------------------
    for assertion in air.get_assertions() {
        assertion.apply(trace.length(), |step, value| {
            assert!(
                value == trace.get(assertion.register(), step),
                "trace does not satisfy assertion trace({}, {}) == {}",
                assertion.register(),
                step,
                value
            );
        });
    }

    // --- 2. make sure this trace satisfies all transition constraints ---------------------------

    // collect the info needed to build periodic values for a specific step
    let g = air.trace_domain_generator();
    let periodic_values_polys = air.get_periodic_column_polys();
    let mut periodic_values = vec![B::ZERO; periodic_values_polys.len()];

    // initialize buffers to hold evaluation frames and results of constraint evaluations
    let mut x = B::ONE;
    let mut ev_frame = EvaluationFrame::new(trace.width());
    let mut evaluations = vec![B::ZERO; air.num_transition_constraints()];

    for step in 0..trace.length() - 1 {
        // build periodic values
        for (p, v) in periodic_values_polys.iter().zip(periodic_values.iter_mut()) {
            let num_cycles = air.trace_length() / p.len();
            let x = x.exp((num_cycles as u32).into());
            *v = math::polynom::eval(p, x);
        }

        // build evaluation frame
        trace.read_row_into(step, ev_frame.current_mut());
        trace.read_row_into(step + 1, ev_frame.next_mut());

        // evaluate transition constraints
        air.evaluate_transition(&ev_frame, &periodic_values, &mut evaluations);

        // make sure all constraints evaluated to ZERO
        for (i, &evaluation) in evaluations.iter().enumerate() {
            assert!(
                evaluation == B::ZERO,
                "transition constraint {} did not evaluate to ZERO at step {}",
                i,
                step
            );
        }

        // update x coordinate of the domain
        x *= g;
    }
}
