// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Assertion, BTreeMap, ExtensionOf, FieldElement, Vec};
use math::{fft, polynom};

// BOUNDARY CONSTRAINT
// ================================================================================================
/// The numerator portion of a boundary constraint.
///
/// A boundary constraint is described by a rational function $\frac{f(x) - b(x)}{z(x)}$, where:
///
/// * $f(x)$ is a trace polynomial for the column against which the constraint is placed.
/// * $b(b)$ is the value polynomial for this constraint.
/// * $z(x)$ is the constraint divisor polynomial.
///
/// In addition to the value polynomial, a [BoundaryConstraint] also contains info needed to
/// evaluate the constraint and to compose constraint evaluations with other constraints (i.e.,
/// constraint composition coefficients).
///
/// When the protocol is run in a large field, types `F` and `E` are the same. However, when
/// working with small fields, `F` and `E` can be set as follows:
/// * `F` could be the base field of the protocol, in which case `E` is the extension field used.
/// * `F` could be the extension field, in which case `F` and `E` are the same type.
///
/// Boundary constraints cannot be instantiated directly, they are created internally from
/// [Assertions](Assertion).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BoundaryConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    column: usize,
    poly: Vec<F>,
    poly_offset: (usize, F::BaseField),
    cc: (E, E),
}

impl<F, E> BoundaryConstraint<F, E>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new boundary constraint from the specified assertion.
    pub(super) fn new(
        assertion: Assertion<F>,
        inv_g: F::BaseField,
        twiddle_map: &mut BTreeMap<usize, Vec<F::BaseField>>,
        composition_coefficients: (E, E),
    ) -> Self {
        // build a polynomial which evaluates to constraint values at asserted steps; for
        // single-value assertions we use the value as constant coefficient of degree 0
        // polynomial; but for multi-value assertions, we need to interpolate the values
        // into a polynomial using inverse FFT
        let mut poly_offset = (0, F::BaseField::ONE);
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
            column: assertion.column,
            poly,
            poly_offset,
            cc: composition_coefficients,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns index of the column against which this constraint applies.
    pub fn column(&self) -> usize {
        self.column
    }

    /// Returns a value polynomial for this constraint.
    pub fn poly(&self) -> &[F] {
        &self.poly
    }

    /// Returns offset by which we need to shift the domain before evaluating this constraint.
    ///
    /// The offset is returned as a tuple describing both, the number of steps by which the
    /// domain needs to be shifted, and field element by which a domain element needs to be
    /// multiplied to achieve the desired shift.
    pub fn poly_offset(&self) -> (usize, F::BaseField) {
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
    /// * $f$ is a trace polynomial for the column against which the constraint is placed.
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
