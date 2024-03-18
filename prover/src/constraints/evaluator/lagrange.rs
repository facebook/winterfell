use air::{
    Air, LagrangeConstraintsCompositionCoefficients, LagrangeKernelBoundaryConstraint,
    LagrangeKernelEvaluationFrame, LagrangeKernelTransitionConstraints,
};
use alloc::vec::Vec;
use math::{batch_inversion, FieldElement};

use crate::StarkDomain;

/// Contains a specific strategy for evaluating the Lagrange kernel boundary and transition
/// constraints where the divisors' evaluation is batched.
///
/// Specifically, [`batch_inversion`] is used to reduce the number of divisions performed.
pub struct LagrangeKernelConstraintsBatchEvaluator<E: FieldElement> {
    boundary_constraint: LagrangeKernelBoundaryConstraint<E>,
    transition_constraints: LagrangeKernelTransitionConstraints<E>,
    rand_elements: Vec<E>,
}

impl<E: FieldElement> LagrangeKernelConstraintsBatchEvaluator<E> {
    /// Constructs a new [`LagrangeConstraintsBatchEvaluator`].
    pub fn new<A: Air>(
        air: &A,
        lagrange_kernel_rand_elements: Vec<E>,
        lagrange_composition_coefficients: LagrangeConstraintsCompositionCoefficients<E>,
    ) -> Self
    where
        E: FieldElement<BaseField = A::BaseField>,
    {
        let lagrange_kernel_transition_constraints = LagrangeKernelTransitionConstraints::new(
            air.context(),
            lagrange_composition_coefficients.transition,
        );
        let lagrange_kernel_boundary_constraint = LagrangeKernelBoundaryConstraint::new(
            lagrange_composition_coefficients.boundary,
            &lagrange_kernel_rand_elements,
        );

        Self {
            boundary_constraint: lagrange_kernel_boundary_constraint,
            transition_constraints: lagrange_kernel_transition_constraints,
            rand_elements: lagrange_kernel_rand_elements,
        }
    }

    /// Evaluates the transition and boundary constraints. Specifically, the constraint evaluations
    /// are divided by their corresponding divisors, and the resulting terms are linearly combined
    /// using the composition coefficients.
    ///
    /// Returns a buffer with the same length as the CE domain, where each element contains the
    /// constraint evaluations (as explained above) at the corresponding domain point.
    pub fn evaluate_lagrange_kernel_constraints<A>(
        &self,
        num_trans_constraints: usize,
        lagrange_kernel_column_frames: Vec<LagrangeKernelEvaluationFrame<E>>,
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E>
    where
        A: Air,
        E: FieldElement<BaseField = A::BaseField>,
    {
        let transition_constraint_combined_evaluations = self
            .evaluate_combined_transition_constraints::<A>(
                num_trans_constraints,
                &lagrange_kernel_column_frames,
                domain,
            );

        let boundary_constraint_combined_evaluations: Vec<E> = self
            .evaluate_combined_boundary_constraints::<A>(&lagrange_kernel_column_frames, domain);

        // combine boundary and transition constraint combined evaluations
        transition_constraint_combined_evaluations
            .into_iter()
            .zip(boundary_constraint_combined_evaluations)
            .map(|(transitions_combined, boundaries_combined)| {
                transitions_combined + boundaries_combined
            })
            .collect()
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Evaluate the transition constraints where the divisors' evaluations are batched to reduce
    /// the number of divisions performed (which has a big effect on performance).
    ///
    /// This algorithm takes advantage of some structure in the divisors' evaluations. Recall that
    /// the divisor for the i'th transition constraint is `x^(2^i) - 1`. When substituting `x` for
    /// each value of the constraint evaluation domain, for constraints `i>0`, the divisor
    /// evaluations "wrap-around" such that some values repeat. For example,
    /// i=0: no repetitions
    /// i=1: the first half of the buffer is equal to the second half
    /// i=2: each 1/4th of the buffer are equal
    /// i=3: each 1/8th of the buffer are equal
    /// ...
    /// Therefore, we only compute the non-repeating section of the buffer in each iteration, and index
    /// into it accordingly.
    fn evaluate_combined_transition_constraints<A>(
        &self,
        num_trans_constraints: usize,
        lagrange_kernel_column_frames: &[LagrangeKernelEvaluationFrame<E>],
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E>
    where
        A: Air,
        E: FieldElement<BaseField = A::BaseField>,
    {
        let mut combined_evaluations_acc = E::zeroed_vector(domain.ce_domain_size());
        let mut denominators: Vec<E> = Vec::with_capacity(domain.ce_domain_size());

        for trans_constraint_idx in 0..num_trans_constraints {
            let num_non_repeating_denoms =
                domain.ce_domain_size() / 2_usize.pow(trans_constraint_idx as u32);

            for step in 0..num_non_repeating_denoms {
                let domain_point = domain.get_ce_x_at(step);
                let denominator = self
                    .transition_constraints
                    .evaluate_ith_divisor(trans_constraint_idx, domain_point);
                denominators.push(denominator);
            }
            let denominators_inv = batch_inversion(&denominators);

            for step in 0..domain.ce_domain_size() {
                let numerator = self.transition_constraints.evaluate_ith_numerator(
                    &lagrange_kernel_column_frames[step],
                    &self.rand_elements,
                    trans_constraint_idx,
                );
                combined_evaluations_acc[step] +=
                    numerator * denominators_inv[step % denominators_inv.len()];
            }

            denominators.truncate(0);
        }

        combined_evaluations_acc
    }

    /// Evaluate the boundary constraint where the divisors' evaluations are batched to reduce the
    /// number of divisions performed (which has a big effect on performance).
    fn evaluate_combined_boundary_constraints<A>(
        &self,
        lagrange_kernel_column_frames: &[LagrangeKernelEvaluationFrame<E>],
        domain: &StarkDomain<A::BaseField>,
    ) -> Vec<E>
    where
        A: Air,
        E: FieldElement<BaseField = A::BaseField>,
    {
        let mut boundary_numerator_evals = Vec::with_capacity(domain.ce_domain_size());
        let mut boundary_denominator_evals = Vec::with_capacity(domain.ce_domain_size());

        for (step, frame) in lagrange_kernel_column_frames.iter().enumerate() {
            let domain_point = domain.get_ce_x_at(step);

            {
                let boundary_numerator = self.boundary_constraint.evaluate_numerator_at(frame);
                boundary_numerator_evals.push(boundary_numerator);
            }

            {
                let boundary_denominator =
                    self.boundary_constraint.evaluate_denominator_at(domain_point.into());
                boundary_denominator_evals.push(boundary_denominator);
            }
        }

        let boundary_denominators_inv = batch_inversion(&boundary_denominator_evals);

        boundary_numerator_evals
            .into_iter()
            .zip(boundary_denominators_inv)
            .map(|(numerator, denom_inv)| numerator * denom_inv)
            .collect()
    }
}
