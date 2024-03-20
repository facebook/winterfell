use math::FieldElement;

use crate::LagrangeKernelEvaluationFrame;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LagrangeKernelBoundaryConstraint<E>
where
    E: FieldElement,
{
    assertion_value: E,
    composition_coefficient: E,
}

impl<E> LagrangeKernelBoundaryConstraint<E>
where
    E: FieldElement,
{
    /// Creates a new Lagrange kernel boundary constraint.
    pub fn new(composition_coefficient: E, lagrange_kernel_rand_elements: &[E]) -> Self {
        Self {
            assertion_value: Self::assertion_value(lagrange_kernel_rand_elements),
            composition_coefficient,
        }
    }

    /// Returns the evaluation of the boundary constraint at `x`, multiplied by the composition coefficient.
    ///
    /// `frame` is the evaluation frame of the Lagrange kernel column `c`, starting at `c(x)`
    pub fn evaluate_at(&self, x: E, frame: &LagrangeKernelEvaluationFrame<E>) -> E {
        let numerator = self.evaluate_numerator_at(frame);
        let denominator = self.evaluate_denominator_at(x);

        numerator / denominator
    }

    /// Returns the evaluation of the boundary constraint numerator, multiplied by the composition coefficient.
    ///
    /// `frame` is the evaluation frame of the Lagrange kernel column `c`, starting at `c(x)` for some `x`
    pub fn evaluate_numerator_at(&self, frame: &LagrangeKernelEvaluationFrame<E>) -> E {
        let trace_value = frame.inner()[0];
        let constraint_evaluation = trace_value - self.assertion_value;

        constraint_evaluation * self.composition_coefficient
    }

    /// Returns the evaluation of the boundary constraint denominator at point `x`.
    pub fn evaluate_denominator_at(&self, x: E) -> E {
        x - E::ONE
    }

    /// Computes the assertion value given the provided random elements.
    pub fn assertion_value(lagrange_kernel_rand_elements: &[E]) -> E {
        let mut assertion_value = E::ONE;
        for &rand_ele in lagrange_kernel_rand_elements {
            assertion_value *= E::ONE - rand_ele;
        }

        assertion_value
    }
}
