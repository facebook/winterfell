use alloc::vec::Vec;

use math::{ExtensionOf, FieldElement};

use crate::{ConstraintDivisor, LagrangeKernelEvaluationFrame};

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
    pub fn new(lagrange_constraint_coefficients: Vec<E>) -> Self {
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

    /// Evaluates the numerator of the `constraint_idx`th transition constraint.
    pub fn evaluate_ith_numerator<F>(
        &self,
        lagrange_kernel_column_frame: &LagrangeKernelEvaluationFrame<E>,
        lagrange_kernel_rand_elements: &[E],
        constraint_idx: usize,
    ) -> E
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        let c = lagrange_kernel_column_frame.inner();
        let v = c.len() - 1;
        let r = lagrange_kernel_rand_elements;
        let k = constraint_idx + 1;

        let eval = (r[v - k] * c[0]) - ((E::ONE - r[v - k]) * c[v - k + 1]);

        self.lagrange_constraint_coefficients[constraint_idx].mul_base(eval)
    }

    /// Evaluates the divisor of the `constraint_idx`th transition constraint.
    pub fn evaluate_ith_divisor<F>(&self, constraint_idx: usize, x: F) -> E
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        self.divisors[constraint_idx].evaluate_at(x.into())
    }

    /// Evaluates the transition constraints over the specificed Lagrange kernel evaluation frame,
    /// and combines them.
    ///
    /// By "combining transition constraints evaluations", we mean computing a linear combination of
    /// each transition constraint evaluation, where each transition evaluation is divided by its
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

    /// Returns the number of constraints.
    pub fn num_constraints(&self) -> usize {
        self.lagrange_constraint_coefficients.len()
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Evaluates the transition constraints' numerators over the specificed Lagrange kernel
    /// evaluation frame.
    fn evaluate_numerators<F>(
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
}
