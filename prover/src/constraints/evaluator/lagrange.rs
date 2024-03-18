use air::{
    Air, LagrangeConstraintsCompositionCoefficients, LagrangeKernelConstraints,
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
    lagrange_kernel_constraints: LagrangeKernelConstraints<E>,
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
        Self {
            lagrange_kernel_constraints: LagrangeKernelConstraints::new(
                air.context(),
                lagrange_composition_coefficients,
                &lagrange_kernel_rand_elements,
            ),
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
                    .lagrange_kernel_constraints
                    .transition
                    .evaluate_ith_divisor(trans_constraint_idx, domain_point);
                denominators.push(denominator);
            }
            let denominators_inv = batch_inversion(&denominators);

            for step in 0..domain.ce_domain_size() {
                let numerator = self.lagrange_kernel_constraints.transition.evaluate_ith_numerator(
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
                let boundary_numerator =
                    self.lagrange_kernel_constraints.boundary.evaluate_numerator_at(frame);
                boundary_numerator_evals.push(boundary_numerator);
            }

            {
                let boundary_denominator = self
                    .lagrange_kernel_constraints
                    .boundary
                    .evaluate_denominator_at(domain_point.into());
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

/// Holds all the transition constraint inverse divisor evaluations over the constraint evaluation domain.
struct LagrangeKernelTransitionConstraintsDivisor<E: FieldElement> {
    divisor_evals_inv: Vec<E>,

    // Precompute the indices into `divisors_evals_inv` of the slices that correspond to each
    // transition constraint.
    //
    // For example, for a CE domain size `n=8`, `slice_indices_precomputes = [0, 8, 12, 14]`, such
    // that transition constraint `idx` owns the range:
    // idx=0: [0, 8)
    // idx=1: [8, 12)
    // idx=2: [12, 14)
    slice_indices_precomputes: Vec<usize>,
}

impl<E: FieldElement> LagrangeKernelTransitionConstraintsDivisor<E> {
    pub fn new(
        lagrange_kernel_transition_constraints: LagrangeKernelTransitionConstraints<E>,
        domain: &StarkDomain<E::BaseField>,
    ) -> Self {
        let divisor_evals_inv = {
            // TODO: Explain why `* 2`
            let mut divisor_evals: Vec<E> = Vec::with_capacity(domain.ce_domain_size() * 2);

            for trans_constraint_idx in 0..lagrange_kernel_transition_constraints.len() {
                let num_non_repeating_denoms =
                    domain.ce_domain_size() / 2_usize.pow(trans_constraint_idx as u32);

                for step in 0..num_non_repeating_denoms {
                    let domain_point = domain.get_ce_x_at(step);
                    // TODO: Are we using precomputed evals in `StarkDomain` as much as we could?
                    let divisor_eval = lagrange_kernel_transition_constraints
                        .evaluate_ith_divisor(trans_constraint_idx, domain_point);

                    divisor_evals.push(divisor_eval);
                }
            }

            batch_inversion(&divisor_evals)
        };

        let slice_indices_precomputes = {
            let num_indices = lagrange_kernel_transition_constraints.len() + 1;
            let mut slice_indices_precomputes = Vec::with_capacity(num_indices);

            slice_indices_precomputes[0] = 0;

            let mut current_slice_len = domain.ce_domain_size();
            for i in 1..num_indices {
                slice_indices_precomputes[i] = slice_indices_precomputes[i - 1] + current_slice_len;

                current_slice_len /= 2;
            }

            slice_indices_precomputes
        };

        Self {
            divisor_evals_inv,
            slice_indices_precomputes,
        }
    }

    /// Returns the evaluation `1 / divisor`, where `divisor` is the divisor for the given
    /// transition constraint, at the given row of the constraint evaluation domain
    pub fn get_inverse_divisor_eval(&self, trans_constraint_idx: usize, row_idx: usize) -> E {
        let inv_divisors_slice_for_constraint =
            self.get_transition_constraint_slice(trans_constraint_idx);

        inv_divisors_slice_for_constraint[row_idx % inv_divisors_slice_for_constraint.len()]
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Returns a slice containing all the inverse divisor evaluations for the given transition
    /// constraint.
    fn get_transition_constraint_slice(&self, trans_constraint_idx: usize) -> &[E] {
        let start = self.slice_indices_precomputes[trans_constraint_idx];
        let end = self.slice_indices_precomputes[trans_constraint_idx + 1];

        &self.divisor_evals_inv[start..end]
    }
}
