// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{
    Air, GkrData, LagrangeConstraintsCompositionCoefficients, LagrangeKernelConstraints,
    LogUpGkrEvaluator,
};
use math::{batch_inversion, FieldElement};

use crate::StarkDomain;

/// Contains a specific strategy for evaluating the Lagrange kernel and s-column boundary and
/// transition constraints.
pub struct LogUpGkrConstraintsEvaluator<E: FieldElement> {
    pub(crate) lagrange_kernel_constraints: LagrangeKernelConstraints<E>,
    pub(crate) gkr_data: GkrData<E>,
    pub(crate) s_col_composition_coefficient: E,
    pub(crate) s_col_idx: usize,
    pub(crate) l_col_idx: usize,
    pub(crate) mean: E,
}

impl<E> LogUpGkrConstraintsEvaluator<E>
where
    E: FieldElement,
{
    /// Constructs a new [`LogUpGkrConstraintsEvaluator`].
    pub fn new<A: Air<BaseField = E::BaseField>>(
        air: &A,
        gkr_data: GkrData<E>,
        lagrange_composition_coefficients: LagrangeConstraintsCompositionCoefficients<E>,
        s_col_composition_coefficient: E,
    ) -> Self {
        let trace_info = air.trace_info();
        let s_col_idx = trace_info.s_column_idx().expect("S-column should be present");
        let l_col_idx = trace_info
            .lagrange_kernel_column_idx()
            .expect("Lagrange kernel should be present");

        let c = gkr_data.compute_batched_claim();
        let mean = c / E::from(E::BaseField::from(trace_info.length() as u32));
        Self {
            lagrange_kernel_constraints: air
                .get_logup_gkr_evaluator()
                .get_lagrange_kernel_constraints(
                    lagrange_composition_coefficients,
                    gkr_data.lagrange_kernel_rand_elements(),
                ),
            gkr_data,
            s_col_composition_coefficient,
            s_col_idx,
            l_col_idx,
            mean,
        }
    }
}

/// Holds all the transition and boundary constraint inverse divisor evaluations over
/// the constraint evaluation domain for both the Lagrange kernel as well the s-column.
///
/// [`LogUpGkrConstraintsDivisors`] takes advantage of some structure in the divisors'
/// evaluations for transition constraints.
/// Recall that the divisor for the i'th transition constraint is `x^(2^i) - 1`.
/// When substituting `x` for each value of the constraint evaluation domain, for constraints
/// `i>0`, the divisor evaluations "wrap-around" such that some values repeat. For example,
///
/// i=0: no repetitions
/// i=1: the first half of the buffer is equal to the second half
/// i=2: each 1/4th of the buffer are equal
/// i=3: each 1/8th of the buffer are equal
/// ...
/// Therefore, we only compute the non-repeating section of the buffer in each iteration, and index
/// into it accordingly.
///
/// Note that instead of storing `1 / div` for Lagrange and s-column transition and boundary
/// constraints, we store instead `c / div` where `c` is the constraint composition coefficient
/// associated to divisor `div`. We call `c / div` constraint evaluation multipliers or just
/// constraint multipliers.
pub(crate) struct LogUpGkrConstraintsDivisors<E: FieldElement> {
    lagrange_transition_multipliers: Vec<E>,

    lagrange_boundary_multipliers: Vec<E>,

    s_col_transition_multipliers: Vec<E>,

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

impl<E: FieldElement> LogUpGkrConstraintsDivisors<E> {
    pub fn new(
        logup_gkr_constraints: &LogUpGkrConstraintsEvaluator<E>,
        domain: &StarkDomain<E::BaseField>,
    ) -> Self {
        let num_lagrange_transition_constraints =
            logup_gkr_constraints.lagrange_kernel_constraints.transition.num_constraints();

        // collect all constraint composition coefficient in order to optimize inversion
        let mut lagrange_transition_cc = logup_gkr_constraints
            .lagrange_kernel_constraints
            .transition
            .lagrange_constraint_coefficients()
            .to_vec();
        let lagrange_boundary_cc = logup_gkr_constraints
            .lagrange_kernel_constraints
            .boundary
            .constraint_composition_coefficient();
        let s_col_cc = logup_gkr_constraints.s_col_composition_coefficient;

        lagrange_transition_cc.push(lagrange_boundary_cc);
        lagrange_transition_cc.push(s_col_cc);

        // batch invert
        let constraint_composition_coefficients = lagrange_transition_cc;
        let constraint_composition_coefficients_inv =
            batch_inversion(&constraint_composition_coefficients);

        let lagrange_cc_inv =
            &constraint_composition_coefficients_inv[..num_lagrange_transition_constraints];
        let lagrange_transition_multipliers = {
            let divisor_evaluator = TransitionDivisorEvaluator::<E>::new(
                num_lagrange_transition_constraints,
                domain.offset(),
            );

            // The number of divisor evaluations is
            // `ce_domain_size + ce_domain_size/2 + ce_domain_size/4 + ... +
            //                                                   ce_domain_size/(log(ce_domain_size)-1)`,
            // which is slightly smaller than `ce_domain_size * 2`.
            // This is also the number of multipliers `c / div` for Lagrange transition constraints
            let mut multipliers: Vec<E> = Vec::with_capacity(domain.ce_domain_size() * 2);

            for (trans_constraint_idx, cc_inv) in lagrange_cc_inv.iter().enumerate() {
                let num_non_repeating_denoms =
                    domain.ce_domain_size() / 2_usize.pow(trans_constraint_idx as u32);

                for step in 0..num_non_repeating_denoms {
                    let divisor_eval =
                        divisor_evaluator.evaluate_ith_divisor(trans_constraint_idx, domain, step);

                    multipliers.push(cc_inv.mul_base(divisor_eval));
                }
            }

            batch_inversion(&multipliers)
        };

        // computes the inverse boundary divisor multiplier by the corresponding constraint
        // composition at every point of the constraint evaluation domain.
        // That is, returns a vector of the form `[c / div_0, ..., c / div_n]`, where `div_i` is the
        // divisor for the Lagrange kernel boundary constraint against the first row at the i'th row
        // of the constraint evaluation domain, and `c` is the constraint evaluation coefficient.
        let lagrange_boundary_multipliers = {
            let mut multipliers = Vec::with_capacity(domain.ce_domain_size());
            for step in 0..domain.ce_domain_size() {
                let domain_point = domain.get_ce_x_at(step);
                let boundary_denominator = domain_point - E::BaseField::ONE;
                let multiplier = constraint_composition_coefficients_inv
                    [num_lagrange_transition_constraints]
                    .mul_base(boundary_denominator);
                multipliers.push(multiplier);
            }

            batch_inversion(&multipliers)
        };

        // compute the divisors for the s-column transition constraint
        let s_col_transition_multipliers = compute_s_col_multipliers(
            domain,
            constraint_composition_coefficients_inv[num_lagrange_transition_constraints + 1],
        );

        let slice_indices_precomputes = {
            let num_indices = num_lagrange_transition_constraints + 1;
            let mut slice_indices_precomputes = Vec::with_capacity(num_indices);

            slice_indices_precomputes.push(0);

            let mut current_slice_len = domain.ce_domain_size();
            for i in 1..num_indices {
                let next_precompute_index = slice_indices_precomputes[i - 1] + current_slice_len;
                slice_indices_precomputes.push(next_precompute_index);

                current_slice_len /= 2;
            }

            slice_indices_precomputes
        };

        Self {
            lagrange_transition_multipliers,
            lagrange_boundary_multipliers,
            slice_indices_precomputes,
            s_col_transition_multipliers,
        }
    }

    /// Returns the evaluation `c / divisor`, where `divisor` is the divisor for the given
    /// Lagrange kernel transition constraint, at the given row of the constraint evaluation domain
    /// and `c` is the corresponding constraint composition coefficient.
    pub fn get_lagrange_transition_multiplier(
        &self,
        trans_constraint_idx: usize,
        row_idx: usize,
    ) -> E {
        let multipliers_slice = self.get_lagrange_transition_constraint_slice(trans_constraint_idx);

        multipliers_slice[row_idx % multipliers_slice.len()]
    }

    /// Returns the evaluation `c / divisor`, where `divisor` runs over all Lagrange kernel
    /// boundary constraint divisors at the given row of the constraint evaluation domain and `c`
    /// is the corresponding constraint composition coefficient.
    pub fn get_lagrange_boundary_multiplier(&self, row_idx: usize) -> E {
        self.lagrange_boundary_multipliers[row_idx % self.lagrange_boundary_multipliers.len()]
    }

    /// Returns the evaluation `c / divisor`, where `divisor` is the divisor for the s-column
    /// transition constraint, at the given row of the constraint evaluation domain and `c` is
    /// the corresponding constraint composition coefficient.
    pub fn get_s_col_transition_multiplier(&self, row_idx: usize) -> E {
        self.s_col_transition_multipliers[row_idx % (self.s_col_transition_multipliers.len())]
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Returns a slice containing all the multipliers evaluations' for the given Lagrange
    /// transition constraint.
    fn get_lagrange_transition_constraint_slice(&self, trans_constraint_idx: usize) -> &[E] {
        let start = self.slice_indices_precomputes[trans_constraint_idx];
        let end = self.slice_indices_precomputes[trans_constraint_idx + 1];

        &self.lagrange_transition_multipliers[start..end]
    }
}

/// Encapsulates the efficient evaluation of the Lagrange kernel transition constraints divisors.
///
/// `s` stands for the domain offset (i.e. coset shift element). The key concept in this
/// optimization is to realize that the computation of the first transition constraint divisor can
/// be reused for all the other divisors (call the evaluations `d`).
///
/// Specifically, each subsequent transition constraint divisor evaluation is equivalent to
/// multiplying an element `d` by a fixed number. For example, the multiplier for the transition
/// constraints are:
///
/// - transition constraint 1's multiplier: s
/// - transition constraint 2's multiplier: s^3
/// - transition constraint 3's multiplier: s^7
/// - transition constraint 4's multiplier: s^15
/// - ...
///
/// This is what `s_precomputes` stores.
///
/// Finally, recall that the ith Lagrange kernel divisor is `x^(2^i) - 1`.
/// [`TransitionDivisorEvaluator`] is only concerned with values of `x` in the constraint evaluation
/// domain, where the j'th element is `s * g^j`, where `g` is the group generator. To understand the
/// implementation of [`Self::evaluate_ith_divisor`], plug in `x = s * g^j` into `x^(2^i) - 1`.
pub struct TransitionDivisorEvaluator<E: FieldElement> {
    s_precomputes: Vec<E::BaseField>,
}

impl<E: FieldElement> TransitionDivisorEvaluator<E> {
    /// Constructs a new [`TransitionDivisorEvaluator`]
    pub fn new(num_lagrange_transition_constraints: usize, domain_offset: E::BaseField) -> Self {
        let s_precomputes = {
            // s_precomputes = [1, s, s^3, s^7, s^15, ...] (where s = domain_offset)
            let mut s_precomputes = Vec::with_capacity(num_lagrange_transition_constraints);

            let mut s_exp = E::BaseField::ONE;
            for _ in 0..num_lagrange_transition_constraints {
                s_precomputes.push(s_exp);
                s_exp = s_exp * s_exp * domain_offset;
            }

            s_precomputes
        };

        Self { s_precomputes }
    }

    /// Evaluates the divisor of the `trans_constraint_idx`'th transition constraint. See
    /// [`TransitionDivisorEvaluator`] for a more in-depth description of the algorithm.
    pub fn evaluate_ith_divisor(
        &self,
        trans_constraint_idx: usize,
        domain: &StarkDomain<E::BaseField>,
        ce_domain_step: usize,
    ) -> E::BaseField {
        let domain_idx = ((1 << trans_constraint_idx) * ce_domain_step) % domain.ce_domain_size();

        self.s_precomputes[trans_constraint_idx] * domain.get_ce_x_at(domain_idx)
            - E::BaseField::ONE
    }
}

/// Computes the evaluations of the s-column multipliers.
///
/// The divisor for the s-column is $X^n - 1$ where $n$ is the trace length. This means that
/// we need only compute `ce_blowup` many values and thus only that many exponentiations.
fn compute_s_col_multipliers<E: FieldElement>(
    domain: &StarkDomain<E::BaseField>,
    composition_coef_inv: E,
) -> Vec<E> {
    let degree = domain.trace_length() as u32;
    let mut result = Vec::with_capacity(domain.trace_to_ce_blowup());

    for row in 0..domain.trace_to_ce_blowup() {
        let divisor = domain.get_ce_x_at(row).exp(degree.into()) - E::BaseField::ONE;

        result.push(composition_coef_inv.mul_base(divisor));
    }
    batch_inversion(&result)
}
