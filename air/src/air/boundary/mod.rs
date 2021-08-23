// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Assertion, ConstraintDivisor};
use math::{fft, polynom, FieldElement, StarkField};
use utils::collections::{BTreeMap, Vec};

#[cfg(test)]
mod tests;

// BOUNDARY CONSTRAINT GROUP
// ================================================================================================
/// A group of boundary constraints all having the same divisor.
///
/// A boundary constraint is described by a rational function $\frac{f(x) - b(x)}{z(x)}$, where:
///
/// * $f(x)$ is a trace polynomial for the register against which the constraint is placed.
/// * $b(x)$ is the value polynomial for the constraint.
/// * $z(x)$ is the constraint divisor polynomial.
///
/// A boundary constraint group groups together all boundary constraints where polynomial $z$ is
/// the same. The constraints stored in the group describe polynomials $b$. At the time of
/// constraint evaluation, a prover or a verifier provides evaluations of the relevant polynomial
/// $f$ so that the value of the constraint can be computed.
#[derive(Debug, Clone)]
pub struct BoundaryConstraintGroup<B: StarkField, E: FieldElement<BaseField = B>> {
    constraints: Vec<BoundaryConstraint<B, E>>,
    divisor: ConstraintDivisor<B>,
    degree_adjustment: u32,
}

impl<B: StarkField, E: FieldElement<BaseField = B>> BoundaryConstraintGroup<B, E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new  boundary constraint group to hold constraints with the specified divisor.
    pub(super) fn new(
        divisor: ConstraintDivisor<B>,
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
    pub fn constraints(&self) -> &[BoundaryConstraint<B, E>] {
        &self.constraints
    }

    /// Returns a divisor applicable to all boundary constraints in this group.
    pub fn divisor(&self) -> &ConstraintDivisor<B> {
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
        assertion: Assertion<B>,
        inv_g: B,
        twiddle_map: &mut BTreeMap<usize, Vec<B>>,
        coefficients: (E, E),
    ) {
        self.constraints.push(BoundaryConstraint::new(
            assertion,
            inv_g,
            twiddle_map,
            coefficients,
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
            let trace_value = state[constraint.register()];
            let evaluation = constraint.evaluate_at(x, trace_value);
            numerator += evaluation * (constraint.cc().0 + constraint.cc().1 * xp);
        }

        let denominator = self.divisor.evaluate_at(x);

        numerator / denominator
    }
}

// BOUNDARY CONSTRAINT
// ================================================================================================
/// The numerator portion of a boundary constraint.
///
/// A boundary constraint is described by a rational function $\frac{f(x) - b(x)}{z(x)}$, where:
///
/// * $f(x)$ is a trace polynomial for the register against which the constraint is placed.
/// * $b(b)$ is the value polynomial for this constraint.
/// * $z(x)$ is the constraint divisor polynomial.
///
/// In addition to the value polynomial, a `BoundaryConstraint` also contains info needed to
/// evaluate the constraint and to compose constraint evaluations with other constraints (i.e.,
/// constraint composition coefficients).
///
/// `BoundaryConstraint`s cannot be instantiated directly, they are created internally from
/// [Assertions](Assertion).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BoundaryConstraint<B: StarkField, E: FieldElement<BaseField = B>> {
    register: usize,
    poly: Vec<B>,
    poly_offset: (usize, B),
    cc: (E, E),
}

impl<B: StarkField, E: FieldElement<BaseField = B>> BoundaryConstraint<B, E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new boundary constraint from the specified assertion.
    pub(super) fn new(
        assertion: Assertion<B>,
        inv_g: B,
        twiddle_map: &mut BTreeMap<usize, Vec<B>>,
        cc: (E, E),
    ) -> Self {
        // build a polynomial which evaluates to constraint values at asserted steps; for
        // single-value assertions we use the value as constant coefficient of degree 0
        // polynomial; but for multi-value assertions, we need to interpolate the values
        // into a polynomial using inverse FFT
        let mut poly_offset = (0, B::ONE);
        let mut poly = assertion.values;
        if poly.len() > 1 {
            // get the twiddles from the map; if twiddles for this domain haven't been built
            // yet, build them and add them to the map
            let inv_twiddles = twiddle_map
                .entry(poly.len())
                .or_insert_with(|| fft::get_inv_twiddles(poly.len()));
            // interpolate the values into a polynomial
            fft::interpolate_poly(&mut poly, inv_twiddles);
            if assertion.first_step != 0 {
                // if the assertions don't fall on the steps which are powers of two, we can't
                // use FFT to interpolate the values into a polynomial. This would make such
                // assertions quite impractical. To get around this, we still use FFT to build
                // the polynomial, but then we evaluate it as f(x * offset) instead of f(x)
                let x_offset = inv_g.exp((assertion.first_step as u64).into());
                poly_offset = (assertion.first_step, x_offset);
            }
        }

        BoundaryConstraint {
            register: assertion.register,
            poly,
            poly_offset,
            cc,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns index of the register against which this constraint applies.
    pub fn register(&self) -> usize {
        self.register
    }

    /// Returns a value polynomial for this constraint.
    pub fn poly(&self) -> &[B] {
        &self.poly
    }

    /// Returns offset by which we need to shift the domain before evaluating this constraint.
    ///
    /// The offset is returned as a tuple describing both, the number of steps by which the
    /// domain needs to be shifted, and field element by which a domain element needs to be
    /// multiplied to achieve the desired shift.
    pub fn poly_offset(&self) -> (usize, B) {
        self.poly_offset
    }

    /// Returns composition coefficients for this constraint.
    pub fn cc(&self) -> &(E, E) {
        &self.cc
    }

    // CONSTRAINT EVALUATOR
    // --------------------------------------------------------------------------------------------
    /// Evaluates this constraint at the specified point `x`.
    ///
    /// The constraint is evaluated by computing $f(x) - b(x)$, where:
    /// * $f$ is a trace polynomial for the register against which the constraint is placed.
    /// * $f(x)$ = `trace_value`
    /// * $b$ is the value polynomial for this constraint.
    ///
    /// For boundary constraints derived from single and periodic assertions, $b(x)$ is a constant.
    pub fn evaluate_at(&self, x: E, trace_value: E) -> E {
        let assertion_value = if self.poly.len() == 1 {
            // if the value polynomial consists of just a constant, use that constant
            E::from(self.poly[0])
        } else {
            // otherwise, we need to evaluate the polynomial at `x`; for assertions which don't
            // fall on steps that are powers of two, we need to evaluate the value polynomial
            // at x * offset (instead of just x).
            //
            // note that while the coefficients of the value polynomial are in the base field,
            // if we are working in an extension field, the result of the evaluation will be a
            // value in the extension field.
            let x = x * E::from(self.poly_offset.1);
            polynom::eval(&self.poly, x)
        };
        // subtract assertion value from trace value
        trace_value - assertion_value
    }
}
