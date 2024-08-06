// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::ops::Index;

use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

// MULTI-LINEAR POLYNOMIAL
// ================================================================================================

/// Represents a multi-linear polynomial.
///
/// The representation stores the evaluations of the polynomial over the boolean hyper-cube
/// ${0 , 1}^ν$.
#[derive(Clone, Debug, PartialEq)]
pub struct MultiLinearPoly<E: FieldElement> {
    evaluations: Vec<E>,
}

impl<E: FieldElement> MultiLinearPoly<E> {
    /// Constructs a [`MultiLinearPoly`] from its evaluations over the boolean hyper-cube ${0 , 1}^ν$.
    pub fn from_evaluations(evaluations: Vec<E>) -> Self {
        assert!(evaluations.len().is_power_of_two(), "A multi-linear polynomial should have a power of 2 number of evaluations over the Boolean hyper-cube");
        Self { evaluations }
    }

    /// Returns the number of variables of the multi-linear polynomial.
    pub fn num_variables(&self) -> usize {
        self.evaluations.len().trailing_zeros() as usize
    }

    /// Returns the evaluations over the boolean hyper-cube.
    pub fn evaluations(&self) -> &[E] {
        &self.evaluations
    }

    /// Returns the number of evaluations. This is equal to the size of the boolean hyper-cube.
    pub fn num_evaluations(&self) -> usize {
        self.evaluations.len()
    }

    /// Evaluate the multi-linear at some query $(r_0, ..., r_{ν - 1}) ∈ 𝔽^ν$.
    ///
    /// It first computes the evaluations of the Lagrange basis polynomials over the interpolating
    /// set ${0 , 1}^ν$ at $(r_0, ..., r_{ν - 1})$ i.e., the Lagrange kernel at $(r_0, ..., r_{ν - 1})$.
    /// The evaluation then is the inner product, indexed by ${0 , 1}^ν$, of the vector of
    /// evaluations times the Lagrange kernel.
    pub fn evaluate(&self, query: &[E]) -> E {
        let tensored_query = compute_lagrange_basis_evals_at(query);
        inner_product(&self.evaluations, &tensored_query)
    }

    /// Similar to [`Self::evaluate`], except that the query was already turned into the Lagrange
    /// kernel (i.e. the [`lagrange_ker::EqFunction`] evaluated at every point in the set
    /// `${0 , 1}^ν$`).
    ///
    /// This is more efficient than [`Self::evaluate`] when multiple different [`MultiLinearPoly`]
    /// need to be evaluated at the same query point.
    pub fn evaluate_with_lagrange_kernel(&self, lagrange_kernel: &[E]) -> E {
        inner_product(&self.evaluations, lagrange_kernel)
    }

    /// Computes $f(r_0, y_1, ..., y_{ν - 1})$ using the linear interpolation formula
    /// $(1 - r_0) * f(0, y_1, ..., y_{ν - 1}) + r_0 * f(1, y_1, ..., y_{ν - 1})$ and assigns
    /// the resulting multi-linear, defined over a domain of half the size, to `self`.
    pub fn bind_least_significant_variable(&mut self, round_challenge: E) {
        let num_evals = self.evaluations.len() >> 1;
        for i in 0..num_evals {
            self.evaluations[i] = self.evaluations[i << 1]
                + round_challenge * (self.evaluations[(i << 1) + 1] - self.evaluations[i << 1]);
        }
        self.evaluations.truncate(num_evals)
    }

    /// Given the multilinear polynomial $f(y_0, y_1, ..., y_{ν - 1})$, returns two polynomials:
    /// $f(0, y_1, ..., y_{ν - 1})$ and $f(1, y_1, ..., y_{ν - 1})$.
    pub fn project_least_significant_variable(&self) -> (Self, Self) {
        let mut p0 = Vec::with_capacity(self.num_evaluations() / 2);
        let mut p1 = Vec::with_capacity(self.num_evaluations() / 2);
        for chunk in self.evaluations.chunks_exact(2) {
            p0.push(chunk[0]);
            p1.push(chunk[1]);
        }

        (MultiLinearPoly::from_evaluations(p0), MultiLinearPoly::from_evaluations(p1))
    }
}

impl<E: FieldElement> Index<usize> for MultiLinearPoly<E> {
    type Output = E;

    fn index(&self, index: usize) -> &E {
        &(self.evaluations[index])
    }
}

// EQ FUNCTION
// ================================================================================================

/// The EQ (equality) function is the binary function defined by
///
/// $$
/// EQ:    {0 , 1}^ν ⛌ {0 , 1}^ν ⇾ {0 , 1}
///   ((x_0, ..., x_{ν - 1}), (y_0, ..., y_{ν - 1})) ↦ \prod_{i = 0}^{ν - 1} (x_i * y_i + (1 - x_i)
/// * (1 - y_i))
/// $$
///
/// Taking its multi-linear extension $EQ^{~}$, we can define a basis for the set of multi-linear
/// polynomials in ν variables by
///         $${EQ^{~}(., (y_0, ..., y_{ν - 1})): (y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν}$$
/// where each basis function is a function of its first argument. This is called the Lagrange or
/// evaluation basis for evaluation set ${0 , 1}^ν$.
///
/// Given a function $(f: {0 , 1}^ν ⇾ 𝔽)$, its multi-linear extension (i.e., the unique
/// mult-linear polynomial extending `f` to $(f^{~}: 𝔽^ν ⇾ 𝔽)$ and agreeing with it on ${0 , 1}^ν$) is
/// defined as the summation of the evaluations of f against the Lagrange basis.
/// More specifically, given $(r_0, ..., r_{ν - 1}) ∈ 𝔽^ν$, then:
///
/// $$
///     f^{~}(r_0, ..., r_{ν - 1}) = \sum_{(y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν}
///                  f(y_0, ..., y_{ν - 1}) EQ^{~}((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1}))
/// $$
///
/// We call the Lagrange kernel the evaluation of the EQ^{~} function at
/// $((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1}))$ for all $(y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν$ for
/// a fixed $(r_0, ..., r_{ν - 1}) ∈ 𝔽^ν$.
///
/// [`EqFunction`] represents EQ^{~} the multi-linear extension of
///
/// $((y_0, ..., y_{ν - 1}) ↦ EQ((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1})))$
///
/// and contains a method to generate the Lagrange kernel for defining evaluations of multi-linear
/// extensions of arbitrary functions $(f: {0 , 1}^ν ⇾ 𝔽)$ at a given point $(r_0, ..., r_{ν - 1})$
/// as well as a method to evaluate $EQ^{~}((r_0, ..., r_{ν - 1}), (t_0, ..., t_{ν - 1})))$ for
/// $(t_0, ..., t_{ν - 1}) ∈ 𝔽^ν$.
pub struct EqFunction<E> {
    r: Vec<E>,
}

impl<E: FieldElement> EqFunction<E> {
    /// Creates a new [EqFunction].
    pub fn new(r: Vec<E>) -> Self {
        let tmp = r.clone();
        EqFunction { r: tmp }
    }

    /// Computes $EQ((r_0, ..., r_{ν - 1}), (t_0, ..., t_{ν - 1})))$.
    pub fn evaluate(&self, t: &[E]) -> E {
        assert_eq!(self.r.len(), t.len());

        (0..self.r.len())
            .map(|i| self.r[i] * t[i] + (E::ONE - self.r[i]) * (E::ONE - t[i]))
            .fold(E::ONE, |acc, term| acc * term)
    }

    /// Computes $EQ((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1}))$ for all
    /// $(y_0, ..., y_{ν - 1}) ∈ {0 , 1}^ν$ i.e., the Lagrange kernel at $r = (r_0, ..., r_{ν - 1})$.
    pub fn evaluations(&self) -> Vec<E> {
        compute_lagrange_basis_evals_at(&self.r)
    }

    /// Returns the evaluations of
    /// $((y_0, ..., y_{ν - 1}) ↦ EQ^{~}((r_0, ..., r_{ν - 1}), (y_0, ..., y_{ν - 1})))$
    /// over ${0 , 1}^ν$.
    pub fn ml_at(evaluation_point: Vec<E>) -> MultiLinearPoly<E> {
        let eq_evals = EqFunction::new(evaluation_point.clone()).evaluations();
        MultiLinearPoly::from_evaluations(eq_evals)
    }
}

// HELPER
// ================================================================================================

/// Computes the evaluations of the Lagrange basis polynomials over the interpolating
/// set ${0 , 1}^ν$ at $(r_0, ..., r_{ν - 1})$ i.e., the Lagrange kernel at $(r_0, ..., r_{ν - 1})$.
///
/// TODO: This is a critical function and parallelizing would have a significant impact on
/// performance.
fn compute_lagrange_basis_evals_at<E: FieldElement>(query: &[E]) -> Vec<E> {
    let nu = query.len();
    let n = 1 << nu;

    let mut evals: Vec<E> = vec![E::ONE; n];
    let mut size = 1;
    for r_i in query.iter().rev() {
        size *= 2;
        for i in (0..size).rev().step_by(2) {
            let scalar = evals[i / 2];
            evals[i] = scalar * *r_i;
            evals[i - 1] = scalar - evals[i];
        }
    }
    evals
}

/// Computes the inner product in the extension field of two slices with the same number of items.
///
/// If `concurrent` feature is enabled, this function can make use of multi-threading.
pub fn inner_product<E: FieldElement>(x: &[E], y: &[E]) -> E {
    #[cfg(not(feature = "concurrent"))]
    return x.iter().zip(y.iter()).fold(E::ZERO, |acc, (x_i, y_i)| acc + *x_i * *y_i);

    #[cfg(feature = "concurrent")]
    return x
        .par_iter()
        .zip(y.par_iter())
        .map(|(x_i, y_i)| *x_i * *y_i)
        .reduce(|| E::ZERO, |a, b| a + b);
}

// TESTS
// ================================================================================================

#[test]
fn multi_linear_sanity_checks() {
    use math::fields::f64::BaseElement;
    let nu = 3;
    let n = 1 << nu;

    // the zero multi-linear should evaluate to zero
    let p = MultiLinearPoly::from_evaluations(vec![BaseElement::ZERO; n]);
    let challenge: Vec<BaseElement> = rand_utils::rand_vector(nu);

    assert_eq!(BaseElement::ZERO, p.evaluate(&challenge));

    // the constant multi-linear should be constant everywhere
    let constant = rand_utils::rand_value();
    let p = MultiLinearPoly::from_evaluations(vec![constant; n]);
    let challenge: Vec<BaseElement> = rand_utils::rand_vector(nu);

    assert_eq!(constant, p.evaluate(&challenge))
}

#[test]
fn test_bind() {
    use math::fields::f64::BaseElement;
    let mut p = MultiLinearPoly::from_evaluations(vec![BaseElement::ONE; 8]);
    let expected = MultiLinearPoly::from_evaluations(vec![BaseElement::ONE; 4]);

    let challenge = rand_utils::rand_value();
    p.bind_least_significant_variable(challenge);
    assert_eq!(p, expected)
}

#[test]
fn test_eq_function() {
    use math::fields::f64::BaseElement;
    use rand_utils::rand_value;

    let one = BaseElement::ONE;

    // Lagrange kernel is computed correctly
    let r0 = rand_value();
    let r1 = rand_value();
    let eq_function = EqFunction::new(vec![r0, r1]);

    let expected = vec![(one - r0) * (one - r1), r0 * (one - r1), (one - r0) * r1, r0 * r1];

    assert_eq!(expected, eq_function.evaluations());

    // Lagrange kernel evaluation is correct
    let q0 = rand_value();
    let q1 = rand_value();
    let tensored_query = vec![(one - q0) * (one - q1), q0 * (one - q1), (one - q0) * q1, q0 * q1];

    let expected = inner_product(&tensored_query, &eq_function.evaluations());

    assert_eq!(expected, eq_function.evaluate(&[q0, q1]))
}
