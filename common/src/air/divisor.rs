// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{air::Assertion, AirContext};
use math::{FieldElement, StarkField};
use std::fmt::{Display, Formatter};

// CONSTRAINT DIVISOR
// ================================================================================================

/// Describes constraint divisor as a combination of a sparse polynomial and exclusion points.
/// For example (x^a - 1) * (x^b - 2) / (x - 3) can be represented as:
///   numerator: vec![(a, 1), (b, 2)]
///   exclude: vec![3]
#[derive(Clone, Debug)]
pub struct ConstraintDivisor<B: StarkField> {
    pub(super) numerator: Vec<(usize, B)>,
    pub(super) exclude: Vec<B>,
}

impl<B: StarkField> ConstraintDivisor<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    pub fn new(numerator: Vec<(usize, B)>, exclude: Vec<B>) -> Self {
        ConstraintDivisor { numerator, exclude }
    }

    /// Builds divisor for transition constraints; the resulting divisor polynomial will be:
    /// (x^trace_length - 1) / (x - x_at_last_step)
    /// this specifies that transition constraints must hold on all steps of the execution trace
    /// except for the last one.
    pub fn from_transition(context: &AirContext) -> Self {
        let trace_length = context.trace_length();
        let x_at_last_step = context.get_trace_domain_value_at::<B>(trace_length - 1);
        ConstraintDivisor {
            numerator: vec![(trace_length, B::ONE)],
            exclude: vec![x_at_last_step],
        }
    }

    /// Builds a divisor for an assertion constraint. The divisor polynomial is defined as:
    /// (x^n - g^(a * n)), where `g` is the generator of the trace domain, `n` is the number
    /// of asserted steps, and `a` is the step offset in the trace domain.
    /// Specifically:
    /// * For an assertion against a single step, the polynomial is (x - g^step), where `step`
    ///   is the step on which the assertion should hold;
    /// * For an assertion against a sequence of steps which fall on powers of two, it is
    ///   (x^n - g^n) where `n` is the number of asserted steps;
    /// * For assertions against a sequence of steps which repeat with a period that is a power
    ///   of two but don't fall exactly on steps which are powers of two (e.g. 1, 7, 15 ...)
    ///   it is (x^n - g^(n * offset)), where `offset` is the number of steps by which the
    ///   assertion steps deviate from a power of two. This is equivalent to
    ///   (x - g^first_step) * (x - g^(first_step + stride)) * (x - g^(first_step + 2 * stride))..
    pub fn from_assertion(assertion: &Assertion<B>, context: &AirContext) -> Self {
        let trace_length = context.trace_length();
        let num_steps = assertion.get_num_steps(trace_length);
        let trace_offset = num_steps * assertion.first_step;
        let offset = context.get_trace_domain_value_at::<B>(trace_offset);
        ConstraintDivisor {
            numerator: vec![(num_steps, offset)],
            exclude: vec![],
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the numerator portion of this constraint divisor.
    pub fn numerator(&self) -> &[(usize, B)] {
        &self.numerator
    }

    /// Returns exclusion points (the denominator portion) of this constraints divisor.
    pub fn exclude(&self) -> &[B] {
        &self.exclude
    }

    /// Returns the degree of the divisor polynomial
    pub fn degree(&self) -> usize {
        let numerator_degree = self
            .numerator
            .iter()
            .fold(0, |degree, term| degree + term.0);
        let denominator_degree = self.exclude.len();
        numerator_degree - denominator_degree
    }

    // EVALUATOR
    // --------------------------------------------------------------------------------------------

    /// Evaluates the divisor at the provided `x` coordinate.
    pub fn evaluate_at<E: FieldElement<BaseField = B>>(&self, x: E) -> E {
        // compute the numerator value
        let mut numerator = E::ONE;
        for (degree, constant) in self.numerator.iter() {
            let v = x.exp((*degree as u32).into());
            let v = v - E::from(*constant);
            numerator *= v;
        }

        // compute the denominator value
        let mut denominator = E::ONE;
        for exception in self.exclude.iter() {
            let v = x - E::from(*exception);
            denominator *= v;
        }

        numerator / denominator
    }
}

impl<B: StarkField> Display for ConstraintDivisor<B> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        for (degree, offset) in self.numerator.iter() {
            write!(f, "(x^{} - {})", degree, offset)?;
        }
        if !self.exclude.is_empty() {
            write!(f, " / ")?;
            for x in self.exclude.iter() {
                write!(f, "(x - {})", x)?;
            }
        }
        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use math::fields::f128::BaseElement;

    #[test]
    fn constraint_divisor_degree() {
        // single term numerator
        let div = ConstraintDivisor::new(vec![(4, BaseElement::ONE)], vec![]);
        assert_eq!(4, div.degree());

        // multi-term numerator
        let div = ConstraintDivisor::new(
            vec![
                (4, BaseElement::ONE),
                (2, BaseElement::new(2)),
                (3, BaseElement::new(3)),
            ],
            vec![],
        );
        assert_eq!(9, div.degree());

        // multi-term numerator with exclusion points
        let div = ConstraintDivisor::new(
            vec![
                (4, BaseElement::ONE),
                (2, BaseElement::new(2)),
                (3, BaseElement::new(3)),
            ],
            vec![BaseElement::ONE, BaseElement::new(2)],
        );
        assert_eq!(7, div.degree());
    }

    #[test]
    fn constraint_divisor_evaluation() {
        // single term numerator: (x^4 - 1)
        let div = ConstraintDivisor::new(vec![(4, BaseElement::ONE)], vec![]);
        assert_eq!(BaseElement::new(15), div.evaluate_at(BaseElement::new(2)));

        // multi-term numerator: (x^4 - 1) * (x^2 - 2) * (x^3 - 3)
        let div = ConstraintDivisor::new(
            vec![
                (4, BaseElement::ONE),
                (2, BaseElement::new(2)),
                (3, BaseElement::new(3)),
            ],
            vec![],
        );
        let expected = BaseElement::new(15) * BaseElement::new(2) * BaseElement::new(5);
        assert_eq!(expected, div.evaluate_at(BaseElement::new(2)));

        // multi-term numerator with exclusion points:
        // (x^4 - 1) * (x^2 - 2) * (x^3 - 3) / ((x - 1) * (x - 2))
        let div = ConstraintDivisor::new(
            vec![
                (4, BaseElement::ONE),
                (2, BaseElement::new(2)),
                (3, BaseElement::new(3)),
            ],
            vec![BaseElement::ONE, BaseElement::new(2)],
        );
        let expected = BaseElement::new(255) * BaseElement::new(14) * BaseElement::new(61)
            / BaseElement::new(6);
        assert_eq!(expected, div.evaluate_at(BaseElement::new(4)));
    }
}
