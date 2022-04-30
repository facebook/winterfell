// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::air::Assertion;
use core::fmt::{Display, Formatter};
use math::{log2, FieldElement, StarkField};
use utils::collections::Vec;

// CONSTRAINT DIVISOR
// ================================================================================================
/// The denominator portion of boundary and transition constraints.
///
/// A divisor is described by a combination of a sparse polynomial, which describes the numerator
/// of the divisor and a set of exemption points, which describe the denominator of the divisor.
/// The numerator polynomial is described as multiplication of tuples where each tuple encodes
/// an expression $(x^a - b)$. The exemption points encode expressions $(x - a)$.
///
/// For example divisor $(x^a - 1) \cdot (x^b - 2) / (x - 3)$ can be represented as:
/// numerator: `[(a, 1), (b, 2)]`, exemptions: `[3]`.
///
/// A divisor cannot be instantiated directly, and instead must be created either for an
/// [Assertion] or for a transition constraint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintDivisor<B: StarkField> {
    pub(super) numerator: Vec<(usize, B)>,
    pub(super) exemptions: Vec<B>,
}

impl<B: StarkField> ConstraintDivisor<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new divisor instantiated from the provided parameters.
    fn new(numerator: Vec<(usize, B)>, exemptions: Vec<B>) -> Self {
        ConstraintDivisor {
            numerator,
            exemptions,
        }
    }

    /// Builds a divisor for transition constraints.
    ///
    /// For transition constraints, the divisor polynomial $z(x)$ is always the same:
    ///
    /// $$
    /// z(x) = \frac{x^n - 1}{ \prod_{i=1}^k (x - g^{n-i})}
    /// $$
    ///
    /// where, $n$ is the length of the execution trace, $g$ is the generator of the trace
    /// domain, and $k$ is the number of exemption points. The default value for $k$ is $1$.
    ///
    /// The above divisor specifies that transition constraints must hold on all steps of the
    /// execution trace except for the last $k$ steps.
    pub fn from_transition(trace_length: usize, num_exemptions: usize) -> Self {
        assert!(
            num_exemptions > 0,
            "invalid number of transition exemptions: must be greater than zero"
        );
        let exemptions = (trace_length - num_exemptions..trace_length)
            .map(|step| get_trace_domain_value_at::<B>(trace_length, step))
            .collect();
        Self::new(vec![(trace_length, B::ONE)], exemptions)
    }

    /// Builds a divisor for a boundary constraint described by the assertion.
    ///
    /// For boundary constraints, the divisor polynomial is defined as:
    ///
    /// $$
    /// z(x) = x^k - g^{a \cdot k}
    /// $$
    ///
    /// where $g$ is the generator of the trace domain, $k$ is the number of asserted steps, and
    /// $a$ is the step offset in the trace domain. Specifically:
    /// * For an assertion against a single step, the polynomial is $(x - g^a)$, where $a$ is the
    ///   step on which the assertion should hold.
    /// * For an assertion against a sequence of steps which fall on powers of two, it is
    ///   $(x^k - 1)$ where $k$ is the number of asserted steps.
    /// * For assertions against a sequence of steps which repeat with a period that is a power
    ///   of two but don't fall exactly on steps which are powers of two (e.g. 1, 9, 17, ... )
    ///   it is $(x^k - g^{a \cdot k})$, where $a$ is the number of steps by which the assertion steps
    ///   deviate from a power of two, and $k$ is the number of asserted steps. This is equivalent to
    ///   $(x - g^a) \cdot (x - g^{a + j}) \cdot (x - g^{a + 2 \cdot j}) ... (x - g^{a + (k  - 1) \cdot j})$,
    ///   where $j$ is the length of interval between asserted steps (e.g. 8).
    ///
    /// # Panics
    /// Panics of the specified `trace_length` is inconsistent with the specified `assertion`.
    pub fn from_assertion<E>(assertion: &Assertion<E>, trace_length: usize) -> Self
    where
        E: FieldElement<BaseField = B>,
    {
        let num_steps = assertion.get_num_steps(trace_length);
        if assertion.first_step == 0 {
            Self::new(vec![(num_steps, B::ONE)], vec![])
        } else {
            let trace_offset = num_steps * assertion.first_step;
            let offset = get_trace_domain_value_at::<B>(trace_length, trace_offset);
            Self::new(vec![(num_steps, offset)], vec![])
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the numerator portion of this constraint divisor.
    pub fn numerator(&self) -> &[(usize, B)] {
        &self.numerator
    }

    /// Returns exemption points (the denominator portion) of this constraints divisor.
    pub fn exemptions(&self) -> &[B] {
        &self.exemptions
    }

    /// Returns the degree of the divisor polynomial
    pub fn degree(&self) -> usize {
        let numerator_degree = self
            .numerator
            .iter()
            .fold(0, |degree, term| degree + term.0);
        let denominator_degree = self.exemptions.len();
        numerator_degree - denominator_degree
    }

    // EVALUATORS
    // --------------------------------------------------------------------------------------------
    /// Evaluates the divisor polynomial at the provided `x` coordinate.
    pub fn evaluate_at<E: FieldElement<BaseField = B>>(&self, x: E) -> E {
        // compute the numerator value
        let mut numerator = E::ONE;
        for (degree, constant) in self.numerator.iter() {
            let v = x.exp((*degree as u32).into());
            let v = v - E::from(*constant);
            numerator *= v;
        }

        // compute the denominator value
        let denominator = self.evaluate_exemptions_at(x);

        numerator / denominator
    }

    /// Evaluates the denominator of this divisor (the exemption points) at the provided `x`
    /// coordinate.
    #[inline(always)]
    pub fn evaluate_exemptions_at<E: FieldElement<BaseField = B>>(&self, x: E) -> E {
        self.exemptions
            .iter()
            .fold(E::ONE, |r, &e| r * (x - E::from(e)))
    }
}

impl<B: StarkField> Display for ConstraintDivisor<B> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        for (degree, offset) in self.numerator.iter() {
            write!(f, "(x^{} - {})", degree, offset)?;
        }
        if !self.exemptions.is_empty() {
            write!(f, " / ")?;
            for x in self.exemptions.iter() {
                write!(f, "(x - {})", x)?;
            }
        }
        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns g^step, where g is the generator of trace domain.
pub fn get_trace_domain_value_at<B: StarkField>(trace_length: usize, step: usize) -> B {
    debug_assert!(
        step < trace_length,
        "step must be in the trace domain [0, {})",
        trace_length
    );
    let g = B::get_root_of_unity(log2(trace_length));
    g.exp((step as u64).into())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use math::{fields::f128::BaseElement, polynom};

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

        // multi-term numerator with exemption points
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

        // multi-term numerator with exemption points:
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

    #[test]
    fn constraint_divisor_equivalence() {
        let n = 8_usize;
        let g = BaseElement::get_root_of_unity(n.trailing_zeros());
        let k = 4 as u32;
        let j = n as u32 / k;

        // ----- periodic assertion divisor, no offset --------------------------------------------

        // create a divisor for assertion which repeats every 2 steps starting at step 0
        let assertion = Assertion::periodic(0, 0, j as usize, BaseElement::ONE);
        let divisor = ConstraintDivisor::from_assertion(&assertion, n);

        // z(x) = x^4 - 1 = (x - 1) * (x - g^2) * (x - g^4) * (x - g^6)
        let poly = polynom::mul(
            &polynom::mul(
                &[-BaseElement::ONE, BaseElement::ONE],
                &[-g.exp(j.into()), BaseElement::ONE],
            ),
            &polynom::mul(
                &[-g.exp((2 * j).into()), BaseElement::ONE],
                &[-g.exp((3 * j).into()), BaseElement::ONE],
            ),
        );

        for i in 0..n {
            let expected = polynom::eval(&poly, g.exp((i as u32).into()));
            let actual = divisor.evaluate_at(g.exp((i as u32).into()));
            assert_eq!(expected, actual);
            if i % (j as usize) == 0 {
                assert_eq!(BaseElement::ZERO, actual);
            }
        }

        // ----- periodic assertion divisor, with offset ------------------------------------------

        // create a divisor for assertion which repeats every 2 steps starting at step 1
        let offset = 1u32;
        let assertion = Assertion::periodic(0, offset as usize, j as usize, BaseElement::ONE);
        let divisor = ConstraintDivisor::from_assertion(&assertion, n);
        assert_eq!(
            ConstraintDivisor::new(vec![(k as usize, g.exp(k.into()))], vec![]),
            divisor
        );

        // z(x) = x^4 - g^4 = (x - g) * (x - g^3) * (x - g^5) * (x - g^7)
        let poly = polynom::mul(
            &polynom::mul(
                &[-g.exp(offset.into()), BaseElement::ONE],
                &[-g.exp((offset + j).into()), BaseElement::ONE],
            ),
            &polynom::mul(
                &[-g.exp((offset + 2 * j).into()), BaseElement::ONE],
                &[-g.exp((offset + 3 * j).into()), BaseElement::ONE],
            ),
        );

        for i in 0..n {
            let expected = polynom::eval(&poly, g.exp((i as u32).into()));
            let actual = divisor.evaluate_at(g.exp((i as u32).into()));
            assert_eq!(expected, actual);
            if i % (j as usize) == offset as usize {
                assert_eq!(BaseElement::ZERO, actual);
            }
        }

        // create a divisor for assertion which repeats every 4 steps starting at step 3
        let offset = 3u32;
        let k = 2 as u32;
        let j = n as u32 / k;
        let assertion = Assertion::periodic(0, offset as usize, j as usize, BaseElement::ONE);
        let divisor = ConstraintDivisor::from_assertion(&assertion, n);
        assert_eq!(
            ConstraintDivisor::new(vec![(k as usize, g.exp((offset * k).into()))], vec![]),
            divisor
        );

        // z(x) = x^2 - g^6 = (x - g^3) * (x - g^7)
        let poly = polynom::mul(
            &[-g.exp(offset.into()), BaseElement::ONE],
            &[-g.exp((offset + j).into()), BaseElement::ONE],
        );

        for i in 0..n {
            let expected = polynom::eval(&poly, g.exp((i as u32).into()));
            let actual = divisor.evaluate_at(g.exp((i as u32).into()));
            assert_eq!(expected, actual);
            if i % (j as usize) == offset as usize {
                assert_eq!(BaseElement::ZERO, actual);
            }
        }
    }
}
