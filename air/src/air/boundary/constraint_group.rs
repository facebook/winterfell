// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{collections::BTreeMap, vec::Vec};

use super::{Assertion, BoundaryConstraint, ConstraintDivisor, ExtensionOf, FieldElement};

// BOUNDARY CONSTRAINT GROUP
// ================================================================================================
/// A group of boundary constraints all having the same divisor.
///
/// A boundary constraint is described by a rational function $\frac{f(x) - b(x)}{z(x)}$, where:
///
/// * $f(x)$ is a trace polynomial for the column against which the constraint is placed.
/// * $b(x)$ is the value polynomial for the constraint.
/// * $z(x)$ is the constraint divisor polynomial.
///
/// A boundary constraint group groups together all boundary constraints where polynomial $z$ is
/// the same. The constraints stored in the group describe polynomials $b$. At the time of
/// constraint evaluation, a prover or a verifier provides evaluations of the relevant polynomial
/// $f$ so that the value of the constraint can be computed.
///
/// When the protocol is run in a large field, types `F` and `E` are the same. However, when
/// working with small fields, `F` and `E` can be set as follows:
/// * `F` could be the base field of the protocol, in which case `E` is the extension field used.
/// * `F` could be the extension field, in which case `F` and `E` are the same type.
///
/// The above arrangement allows us to describe boundary constraints for main and auxiliary
/// segments of the execution trace. Specifically:
/// * For the constraints against columns of the main execution trace, `F` is set to the base field
///   of the protocol, and `E` is set to the extension field.
/// * For the constraints against columns of the auxiliary trace segment, both `F` and `E` are set
///   to the extension field.
#[derive(Debug, Clone)]
pub struct BoundaryConstraintGroup<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    constraints: Vec<BoundaryConstraint<F, E>>,
    divisor: ConstraintDivisor<F::BaseField>,
}

impl<F, E> BoundaryConstraintGroup<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new boundary constraint group to hold constraints with the specified divisor.
    pub(super) fn new(divisor: ConstraintDivisor<F::BaseField>) -> Self {
        BoundaryConstraintGroup { constraints: Vec::new(), divisor }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a list of boundary constraints in this group.
    pub fn constraints(&self) -> &[BoundaryConstraint<F, E>] {
        &self.constraints
    }

    /// Returns a divisor applicable to all boundary constraints in this group.
    pub fn divisor(&self) -> &ConstraintDivisor<F::BaseField> {
        &self.divisor
    }

    // PUBLIC METHODS
    // --------------------------------------------------------------------------------------------

    /// Creates a new boundary constraint from the specified assertion and adds it to the group.
    pub(super) fn add(
        &mut self,
        assertion: Assertion<F>,
        inv_g: F::BaseField,
        twiddle_map: &mut BTreeMap<usize, Vec<F::BaseField>>,
        composition_coefficients: E,
    ) {
        self.constraints.push(BoundaryConstraint::new(
            assertion,
            inv_g,
            twiddle_map,
            composition_coefficients,
        ));
    }

    /// Evaluates all constraints in this group at the specified point `x`.
    ///
    /// Constraint evaluations are merges into a single value by computing their random linear
    /// combination and dividing the result by the divisor of this constraint group as follows:
    /// $$
    /// \frac{\sum_{i=0}^{k-1}{\alpha_i \cdot C_i(x)}}{z(x)}
    /// $$
    /// where:
    /// * $C_i(x)$ is the evaluation of the $i$th constraint at `x` computed as $f(x) - b(x)$.
    /// * $\alpha_i$ are random field elements. In the interactive version of the protocol, these
    ///   are provided by the verifier.
    pub fn evaluate_at(&self, state: &[E], x: E) -> E {
        let mut numerator = E::ZERO;
        for constraint in self.constraints().iter() {
            let trace_value = state[constraint.column()];
            let evaluation = constraint.evaluate_at(x, trace_value);
            numerator += evaluation * *constraint.cc();
        }

        let denominator = self.divisor.evaluate_at(x);

        numerator / denominator
    }
}
