// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::Air;
use math::{fft, polynom, FieldElement, StarkField};
use utils::collections::{BTreeMap, Vec};

// CONSTANTS
// ================================================================================================

/// Boundary polynomials with this degree or smaller will be evaluated on the fly, while for
/// larger polynomials all evaluations over the constraint evaluation domain will be pre-computed.
const SMALL_POLY_DEGREE: usize = 63;

// BOUNDARY CONSTRAINT GROUP
// ================================================================================================

/// Contains constraints all having the same divisor. The constraints are separated into single
/// value constraints, small polynomial constraints, and large polynomial constraints.
pub struct BoundaryConstraintGroup<B: StarkField, E: FieldElement<BaseField = B>> {
    pub(super) degree_adjustment: u32,
    single_value_constraints: Vec<SingleValueConstraint<B, E>>,
    small_poly_constraints: Vec<SmallPolyConstraint<B, E>>,
    large_poly_constraints: Vec<LargePolyConstraint<B, E>>,
}

impl<B: StarkField, E: FieldElement<BaseField = B>> BoundaryConstraintGroup<B, E> {
    /// Creates a new specialized constraint group; twiddles and ce_blowup_factor are passed in for
    /// evaluating large polynomial constraints (if any).
    pub fn new<A: Air<BaseField = B>>(
        group: air::BoundaryConstraintGroup<B, E>,
        air: &A,
        twiddle_map: &mut BTreeMap<usize, Vec<B>>,
    ) -> BoundaryConstraintGroup<B, E> {
        let mut result = BoundaryConstraintGroup {
            degree_adjustment: group.degree_adjustment(),
            single_value_constraints: Vec::new(),
            small_poly_constraints: Vec::new(),
            large_poly_constraints: Vec::new(),
        };

        for constraint in group.constraints() {
            if constraint.poly().len() == 1 {
                result.single_value_constraints.push(SingleValueConstraint {
                    register: constraint.register(),
                    value: constraint.poly()[0],
                    coefficients: *constraint.cc(),
                });
            } else if constraint.poly().len() < SMALL_POLY_DEGREE {
                result.small_poly_constraints.push(SmallPolyConstraint {
                    register: constraint.register(),
                    poly: constraint.poly().to_vec(),
                    x_offset: constraint.poly_offset().1,
                    coefficients: *constraint.cc(),
                });
            } else {
                // evaluate the polynomial over the entire constraint evaluation domain; first
                // get twiddles for the evaluation; if twiddles haven't been built yet, build them
                let poly_length = constraint.poly().len();
                let twiddles = twiddle_map
                    .entry(poly_length)
                    .or_insert_with(|| fft::get_twiddles(poly_length));

                let values = fft::evaluate_poly_with_offset(
                    constraint.poly(),
                    twiddles,
                    air.domain_offset(),
                    air.ce_domain_size() / poly_length,
                );

                result.large_poly_constraints.push(LargePolyConstraint {
                    register: constraint.register(),
                    values,
                    step_offset: constraint.poly_offset().0 * air.ce_blowup_factor(),
                    coefficients: *constraint.cc(),
                });
            }
        }

        result
    }

    /// Evaluates the constraints contained in this group at the specified step of the
    /// execution trace.
    pub fn evaluate(&self, state: &[B], ce_step: usize, x: B, xp: E) -> E {
        let mut result = E::ZERO;

        // evaluate all single-value constraints
        for constraint in self.single_value_constraints.iter() {
            result += constraint.evaluate(state, xp);
        }

        // evaluate all small polynomial constraints
        for constraint in self.small_poly_constraints.iter() {
            result += constraint.evaluate(state, x, xp);
        }

        // evaluate all large polynomial constraints
        for constraint in self.large_poly_constraints.iter() {
            result += constraint.evaluate(state, ce_step, xp);
        }

        result
    }
}

// CONSTRAINT SPECIALIZATIONS
// ================================================================================================

/// A constraint where the numerator can be represented by p(x) - v, where v is the asserted value,
/// and p(x) is the trace polynomial for the register against which the constraint is applied.
struct SingleValueConstraint<B: StarkField, E: FieldElement<BaseField = B>> {
    register: usize,
    value: B,
    coefficients: (E, E),
}

impl<B: StarkField, E: FieldElement<BaseField = B>> SingleValueConstraint<B, E> {
    pub fn evaluate(&self, state: &[B], xp: E) -> E {
        let evaluation = E::from(state[self.register] - self.value);
        evaluation * (self.coefficients.0 + self.coefficients.1 * xp)
    }
}

/// A constraint where the numerator can be represented by p(x) - c(x), where c(x) is the
/// polynomial describing a set of asserted values. This specialization is useful when the
// degree of c(x) is relatively small, and thus, is cheap to evaluate on the fly.
struct SmallPolyConstraint<B: StarkField, E: FieldElement<BaseField = B>> {
    register: usize,
    poly: Vec<B>,
    x_offset: B,
    coefficients: (E, E),
}

impl<B: StarkField, E: FieldElement<BaseField = B>> SmallPolyConstraint<B, E> {
    pub fn evaluate(&self, state: &[B], x: B, xp: E) -> E {
        let x = x * self.x_offset;
        // evaluate constraint polynomial as x * offset
        let assertion_value = polynom::eval(&self.poly, x);
        let evaluation = E::from(state[self.register] - assertion_value);
        evaluation * (self.coefficients.0 + self.coefficients.1 * xp)
    }
}

/// A constraint where the numerator can be represented by p(x) - c(x), where c(x) is a large
/// polynomial. In such cases, we pre-compute evaluations of c(x) by evaluating it over the
/// entire constraint evaluation domain (using FFT).
struct LargePolyConstraint<B: StarkField, E: FieldElement<BaseField = B>> {
    register: usize,
    values: Vec<B>,
    step_offset: usize,
    coefficients: (E, E),
}

impl<B: StarkField, E: FieldElement<BaseField = B>> LargePolyConstraint<B, E> {
    pub fn evaluate(&self, state: &[B], ce_step: usize, xp: E) -> E {
        let value_index = if self.step_offset > 0 {
            // if the assertion happens on steps which are not a power of 2, we need to offset the
            // evaluation; the below basically computes (ce_step - step_offset) % values.len();
            // this is equivalent to evaluating the polynomial at x * x_offset coordinate.
            if self.step_offset > ce_step {
                self.values.len() + ce_step - self.step_offset
            } else {
                ce_step - self.step_offset
            }
        } else {
            ce_step
        };
        let evaluation = E::from(state[self.register] - self.values[value_index]);
        evaluation * (self.coefficients.0 + self.coefficients.1 * xp)
    }
}
