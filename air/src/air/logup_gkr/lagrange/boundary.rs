// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::FieldElement;

use super::{LagrangeKernelEvaluationFrame, LagrangeKernelRandElements};

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
    pub fn new(
        composition_coefficient: E,
        lagrange_kernel_rand_elements: &LagrangeKernelRandElements<E>,
    ) -> Self {
        Self {
            assertion_value: Self::assertion_value(lagrange_kernel_rand_elements),
            composition_coefficient,
        }
    }

    /// Returns the constraint composition coefficient for this boundary constraint.
    pub fn constraint_composition_coefficient(&self) -> E {
        self.composition_coefficient
    }

    /// Returns the evaluation of the boundary constraint at `x`, multiplied by the composition
    /// coefficient.
    ///
    /// `frame` is the evaluation frame of the Lagrange kernel column `c`, starting at `c(x)`
    pub fn evaluate_at(&self, x: E, frame: &LagrangeKernelEvaluationFrame<E>) -> E {
        let numerator = self.evaluate_numerator_at(frame) * self.composition_coefficient;
        let denominator = self.evaluate_denominator_at(x);

        numerator / denominator
    }

    /// Returns the evaluation of the boundary constraint numerator.
    ///
    /// `frame` is the evaluation frame of the Lagrange kernel column `c`, starting at `c(x)` for
    /// some `x`
    pub fn evaluate_numerator_at(&self, frame: &LagrangeKernelEvaluationFrame<E>) -> E {
        frame[0] - self.assertion_value
    }

    /// Returns the evaluation of the boundary constraint denominator at point `x`.
    pub fn evaluate_denominator_at(&self, x: E) -> E {
        x - E::ONE
    }

    /// Computes the assertion value given the provided random elements.
    pub fn assertion_value(lagrange_kernel_rand_elements: &LagrangeKernelRandElements<E>) -> E {
        let mut assertion_value = E::ONE;
        for &rand_ele in lagrange_kernel_rand_elements.as_ref() {
            assertion_value *= E::ONE - rand_ele;
        }

        assertion_value
    }
}
