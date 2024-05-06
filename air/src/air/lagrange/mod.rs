// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod boundary;
use core::ops::Deref;

use alloc::vec::Vec;
pub use boundary::LagrangeKernelBoundaryConstraint;

mod frame;
pub use frame::LagrangeKernelEvaluationFrame;

mod transition;
use math::FieldElement;
pub use transition::LagrangeKernelTransitionConstraints;

use crate::LagrangeConstraintsCompositionCoefficients;

/// Represents the Lagrange kernel transition and boundary constraints.
pub struct LagrangeKernelConstraints<E: FieldElement> {
    pub transition: LagrangeKernelTransitionConstraints<E>,
    pub boundary: LagrangeKernelBoundaryConstraint<E>,
    pub lagrange_kernel_col_idx: usize,
}

impl<E: FieldElement> LagrangeKernelConstraints<E> {
    /// Constructs a new [`LagrangeKernelConstraints`].
    pub fn new(
        lagrange_composition_coefficients: LagrangeConstraintsCompositionCoefficients<E>,
        lagrange_kernel_rand_elements: &[E],
        lagrange_kernel_col_idx: usize,
    ) -> Self {
        Self {
            transition: LagrangeKernelTransitionConstraints::new(
                lagrange_composition_coefficients.transition,
            ),
            boundary: LagrangeKernelBoundaryConstraint::new(
                lagrange_composition_coefficients.boundary,
                lagrange_kernel_rand_elements,
            ),
            lagrange_kernel_col_idx,
        }
    }
}

/// TODOP: Document
#[derive(Debug, Clone)]
pub struct LagrangeRandElements<E> {
    elements: Vec<E>,
}

impl<E> LagrangeRandElements<E> {
    pub fn new(elements: Vec<E>) -> Self {
        Self { elements }
    }
}

impl<E> Deref for LagrangeRandElements<E> {
    type Target = Vec<E>;

    fn deref(&self) -> &Self::Target {
        &self.elements
    }
}

impl<E> AsRef<[E]> for LagrangeRandElements<E> {
    fn as_ref(&self) -> &[E] {
        &self.elements
    }
}

impl<E> From<LagrangeRandElements<E>> for Vec<E> {
    fn from(lagrange_rand_elements: LagrangeRandElements<E>) -> Self {
        lagrange_rand_elements.elements
    }
}
