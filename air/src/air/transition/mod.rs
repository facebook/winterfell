// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use super::{AirContext, ConstraintDivisor, ExtensionOf, FieldElement};

mod frame;
pub use frame::EvaluationFrame;

mod degree;
pub use degree::TransitionConstraintDegree;

// CONSTANTS
// ================================================================================================

const MIN_CYCLE_LENGTH: usize = 2;

// TRANSITION CONSTRAINTS INFO
// ================================================================================================

/// Metadata for transition constraints of a computation.
///
/// This metadata includes:
/// - List of transition constraint degrees for the main trace segment, as well as for auxiliary
///   trace segments (if any).
/// - Groupings of random composition constraint coefficients separately for the main trace segment
///   and for auxiliary tace segment.
/// - Divisor of transition constraints for a computation.
pub struct TransitionConstraints<E: FieldElement> {
    main_constraint_coef: Vec<E>,
    aux_constraint_coef: Vec<E>,
    divisor: ConstraintDivisor<E::BaseField>,
}

impl<E: FieldElement> TransitionConstraints<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [TransitionConstraints] for a computation described by the
    /// specified AIR context.
    ///
    /// # Panics
    /// Panics if the number of transition constraints in the context does not match the number of
    /// provided composition coefficients.
    pub fn new(context: &AirContext<E::BaseField>, composition_coefficients: &[E]) -> Self {
        // build constraint divisor; the same divisor applies to all transition constraints
        let divisor = ConstraintDivisor::from_transition(
            context.trace_len(),
            context.num_transition_exemptions(),
        );

        let (main_constraint_coef, aux_constraint_coef) =
            composition_coefficients.split_at(context.num_main_transition_constraints);
        Self {
            main_constraint_coef: main_constraint_coef.to_vec(),
            aux_constraint_coef: aux_constraint_coef.to_vec(),
            divisor,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of constraints applied against the main trace segment of a computation.
    pub fn num_main_constraints(&self) -> usize {
        self.main_constraint_coef.len()
    }

    /// Returns the random coefficients for constraints applied against main trace segment of a
    /// computation.
    pub fn main_constraint_coef(&self) -> Vec<E> {
        self.main_constraint_coef.clone()
    }

    /// Returns the number of constraints applied against the auxiliary trace segment of a
    /// computation.
    pub fn num_aux_constraints(&self) -> usize {
        self.aux_constraint_coef.len()
    }

    /// Returns the random coefficients for constraints applied against the auxiliary trace segment of a
    /// computation.
    pub fn aux_constraint_coef(&self) -> Vec<E> {
        self.aux_constraint_coef.clone()
    }

    /// Returns a divisor for transition constraints.
    ///
    /// All transition constraints have the same divisor which has the form:
    /// $$
    /// z(x) = \frac{x^n - 1}{x - g^{n - 1}}
    /// $$
    /// where: $n$ is the length of the execution trace and $g$ is the generator of the trace
    /// domain.
    ///
    /// This divisor specifies that transition constraints must hold on all steps of the
    /// execution trace except for the last one.
    pub fn divisor(&self) -> &ConstraintDivisor<E::BaseField> {
        &self.divisor
    }

    // CONSTRAINT COMPOSITION
    // --------------------------------------------------------------------------------------------

    /// Computes a linear combination of all transition constraint evaluations and divides the
    /// result by transition constraint divisor.
    ///
    /// A transition constraint is described by a rational function of the form $\frac{C(x)}{z(x)}$,
    /// where:
    /// * $C(x)$ is the constraint polynomial.
    /// * $z(x)$ is the constraint divisor polynomial.
    ///
    /// Thus, this function computes a linear combination of $C(x)$ evaluations.
    ///
    /// Since, the divisor polynomial is the same for all transition constraints (see
    /// [ConstraintDivisor::from_transition]), we can divide the linear combination by the
    /// divisor rather than dividing each individual $C(x)$ evaluation. This requires executing only
    /// one division at the end.
    pub fn combine_evaluations<F>(&self, main_evaluations: &[F], aux_evaluations: &[E], x: F) -> E
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        // merge constraint evaluations for the main trace segment
        let mut result = main_evaluations
            .iter()
            .zip(self.main_constraint_coef.iter())
            .fold(E::ZERO, |acc, (&const_eval, &coef)| acc + coef.mul_base(const_eval));

        if !self.aux_constraint_coef.is_empty() {
            result += aux_evaluations
                .iter()
                .zip(self.aux_constraint_coef.iter())
                .fold(E::ZERO, |acc, (&const_eval, &coef)| acc + coef * const_eval);
        };
        // divide out the evaluation of divisor at x and return the result
        let z = E::from(self.divisor.evaluate_at(x));

        result / z
    }
}
