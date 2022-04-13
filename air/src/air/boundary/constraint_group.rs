// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{
    Assertion, BTreeMap, BoundaryConstraint, ConstraintDivisor, ExtensionOf, FieldElement, Vec,
};

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
/// * For the constraints against columns of auxiliary trace segments, both `F` and `E` are set to
///   the extension field.
#[derive(Debug, Clone)]
pub struct BoundaryConstraintGroup<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    constraints: Vec<BoundaryConstraint<F, E>>,
    divisor: ConstraintDivisor<F::BaseField>,
    degree_adjustment: u32,
}

impl<F, E> BoundaryConstraintGroup<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new  boundary constraint group to hold constraints with the specified divisor.
    pub(super) fn new(
        divisor: ConstraintDivisor<F::BaseField>,
        trace_poly_degree: usize,
        composition_degree: usize,
    ) -> Self {
        // We want to make sure that once we divide a constraint polynomial by its divisor, the
        // degree of the resulting polynomial will be exactly equal to the composition_degree.
        // Boundary constraint degree is always deg(trace). So, the degree adjustment is simply:
        // deg(composition) + deg(divisor) - deg(trace)
        let target_degree = composition_degree + divisor.degree();
        let degree_adjustment = (target_degree - trace_poly_degree) as u32;

        BoundaryConstraintGroup {
            constraints: Vec::new(),
            divisor,
            degree_adjustment,
        }
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

    /// Returns a degree adjustment factor for all boundary constraints in this group.
    pub fn degree_adjustment(&self) -> u32 {
        self.degree_adjustment
    }

    // PUBLIC METHODS
    // --------------------------------------------------------------------------------------------

    /// Creates a new boundary constraint from the specified assertion and adds it to the group.
    pub(super) fn add(
        &mut self,
        assertion: Assertion<F>,
        inv_g: F::BaseField,
        twiddle_map: &mut BTreeMap<usize, Vec<F::BaseField>>,
        composition_coefficients: (E, E),
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
    /// `xp` is a degree adjustment multiplier which must be computed as `x^degree_adjustment`.
    /// This value is provided as an argument to this function for optimization purposes.
    ///
    /// Constraint evaluations are merges into a single value by computing their random linear
    /// combination and dividing the result by the divisor of this constraint group as follows:
    /// $$
    /// \frac{\sum_{i=0}^{k-1}{C_i(x) \cdot (\alpha_i + \beta_i \cdot x^d)}}{z(x)}
    /// $$
    /// where:
    /// * $C_i(x)$ is the evaluation of the $i$th constraint at `x` computed as $f(x) - b(x)$.
    /// * $\alpha$ and $\beta$ are random field elements. In the interactive version of the
    ///   protocol, these are provided by the verifier.
    /// * $z(x)$ is the evaluation of the divisor polynomial for this group at $x$.
    /// * $d$ is the degree adjustment factor computed as $D - deg(C_i(x)) + deg(z(x))$, where
    ///   $D$ is the degree of the composition polynomial.
    ///
    /// Thus, the merged evaluations represent a polynomial of degree $D$, as the degree of the
    /// numerator is $D + deg(z(x))$, and the division by $z(x)$ reduces the degree by $deg(z(x))$.
    pub fn evaluate_at(&self, state: &[E], x: E, xp: E) -> E {
        debug_assert_eq!(
            x.exp(self.degree_adjustment.into()),
            xp,
            "inconsistent degree adjustment"
        );
        let mut numerator = E::ZERO;
        for constraint in self.constraints().iter() {
            let trace_value = state[constraint.column()];
            let evaluation = constraint.evaluate_at(x, trace_value);
            numerator += evaluation * (constraint.cc().0 + constraint.cc().1 * xp);
        }

        let denominator = self.divisor.evaluate_at(x);

        numerator / denominator
    }
}
