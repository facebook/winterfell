// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{AirContext, ConstraintDivisor, ExtensionOf, FieldElement};
use utils::collections::*;

mod frame;
pub use frame::{EvaluationFrame, LagrangeKernelEvaluationFrame};

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
    main_constraint_degrees: Vec<TransitionConstraintDegree>,
    aux_constraint_coef: Vec<E>,
    aux_constraint_degrees: Vec<TransitionConstraintDegree>,
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
        assert_eq!(
            context.num_transition_constraints(),
            composition_coefficients.len(),
            "number of transition constraints must match the number of composition coefficient tuples"
        );

        // build constraint divisor; the same divisor applies to all transition constraints
        let divisor = ConstraintDivisor::from_transition(
            context.trace_len(),
            context.num_transition_exemptions(),
        );

        let main_constraint_degrees = context.main_transition_constraint_degrees.clone();
        let aux_constraint_degrees = context.aux_transition_constraint_degrees.clone();

        let (main_constraint_coef, aux_constraint_coef) =
            composition_coefficients.split_at(context.main_transition_constraint_degrees.len());
        Self {
            main_constraint_coef: main_constraint_coef.to_vec(),
            main_constraint_degrees,
            aux_constraint_coef: aux_constraint_coef.to_vec(),
            aux_constraint_degrees,
            divisor,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a list of transition constraint degree descriptors for the main trace segment of
    /// a computation.
    ///
    /// This list will be identical to the list passed into the [AirContext::new()] method as
    /// the `transition_constraint_degrees` parameter, or into [AirContext::new_multi_segment()]
    /// as the `main_transition_constraint_degrees` parameter.
    pub fn main_constraint_degrees(&self) -> &[TransitionConstraintDegree] {
        &self.main_constraint_degrees
    }

    /// Returns the number of constraints applied against the main trace segment of a computation.
    pub fn num_main_constraints(&self) -> usize {
        self.main_constraint_degrees.len()
    }

    /// Returns the random coefficients for constraints applied against main trace segment of a
    /// computation.
    pub fn main_constraint_coef(&self) -> Vec<E> {
        self.main_constraint_coef.clone()
    }

    /// Returns a list of transition constraint degree descriptors for auxiliary trace segments of
    /// a computation.
    ///
    /// This list will be identical to the list passed into [AirContext::new_multi_segment()]
    /// as the `aux_transition_constraint_degrees` parameter.
    pub fn aux_constraint_degrees(&self) -> &[TransitionConstraintDegree] {
        &self.aux_constraint_degrees
    }

    /// Returns the number of constraints applied against auxiliary trace segments of a
    /// computation.
    pub fn num_aux_constraints(&self) -> usize {
        self.aux_constraint_degrees.len()
    }

    /// Returns the random coefficients for constraints applied against auxiliary trace segments of a
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

// LAGRANGE KERNEL TRANSITION CONSTRAINTS INFO
// ================================================================================================

/// Represents the transition constraints for the Lagrange kernel column, as well as the random
/// coefficients used to linearly combine all the constraints.
///
/// There are `log(trace_len)` constraints, each with its own divisor, as described in
/// [this issue](https://github.com/facebook/winterfell/issues/240).
pub struct LagrangeKernelTransitionConstraints<E: FieldElement> {
    lagrange_constraint_coefficients: Vec<E>,
    divisors: Vec<ConstraintDivisor<E::BaseField>>,
}

impl<E: FieldElement> LagrangeKernelTransitionConstraints<E> {
    /// Creates a new [`LagrangeKernelTransitionConstraints`], which represents the Lagrange kernel
    /// transition constraints as well as the random coefficients necessary to combine the
    /// constraints together.
    pub fn new(
        context: &AirContext<E::BaseField>,
        lagrange_constraint_coefficients: Vec<E>,
    ) -> Self {
        assert_eq!(context.trace_len().ilog2(), lagrange_constraint_coefficients.len() as u32);

        let num_lagrange_kernel_transition_constraints = lagrange_constraint_coefficients.len();

        let divisors = {
            let mut divisors = Vec::with_capacity(num_lagrange_kernel_transition_constraints);
            for i in 0..num_lagrange_kernel_transition_constraints {
                let constraint_domain_size = 2_usize.pow(i as u32);
                let divisor = ConstraintDivisor::from_transition(constraint_domain_size, 0);

                divisors.push(divisor);
            }
            divisors
        };

        Self {
            lagrange_constraint_coefficients,
            divisors,
        }
    }

    /// Evaluates the transition constraints' numerators over the specificed Lagrange kernel
    /// evaluation frame.
    pub fn evaluate_numerators<F>(
        &self,
        lagrange_kernel_column_frame: &LagrangeKernelEvaluationFrame<E>,
        lagrange_kernel_rand_elements: &[E],
    ) -> Vec<E>
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        let log2_trace_len = lagrange_kernel_column_frame.num_rows() - 1;
        let mut transition_evals = E::zeroed_vector(log2_trace_len);

        let c = lagrange_kernel_column_frame.inner();
        let v = c.len() - 1;
        let r = lagrange_kernel_rand_elements;

        for k in 1..v + 1 {
            transition_evals[k - 1] = (r[v - k] * c[0]) - ((E::ONE - r[v - k]) * c[v - k + 1]);
        }

        transition_evals
            .into_iter()
            .zip(self.lagrange_constraint_coefficients.iter())
            .map(|(transition_eval, &coeff)| coeff.mul_base(transition_eval))
            .collect()
    }

    /// Evaluates the transition constraints over the specificed Lagrange kernel evaluation frame,
    /// and combines them.
    ///
    /// By "combining transition constraints evaluations", we mean computing a linear combination of
    /// all transition constraint evaluations, where each transition evaluation is divided by its
    /// corresponding divisor.
    pub fn evaluate_and_combine<F>(
        &self,
        lagrange_kernel_column_frame: &LagrangeKernelEvaluationFrame<E>,
        lagrange_kernel_rand_elements: &[E],
        x: F,
    ) -> E
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        let numerators = self
            .evaluate_numerators::<F>(lagrange_kernel_column_frame, lagrange_kernel_rand_elements);

        numerators
            .iter()
            .zip(self.divisors.iter())
            .fold(E::ZERO, |acc, (&numerator, divisor)| {
                let z = divisor.evaluate_at(x);

                acc + (numerator / z.into())
            })
    }
}
