// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::ops::Index;

use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use smallvec::SmallVec;
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// MULTI-LINEAR POLYNOMIAL
// ================================================================================================

/// Represents a multi-linear polynomial.
///
/// The representation stores the evaluations of the polynomial over the boolean hyper-cube
/// ${0 , 1}^{\nu}$.
#[derive(Clone, Debug, PartialEq)]
pub struct MultiLinearPoly<E: FieldElement> {
    evaluations: Vec<E>,
}

impl<E: FieldElement> MultiLinearPoly<E> {
    /// Constructs a [`MultiLinearPoly`] from its evaluations over the boolean hyper-cube ${0 , 1}^{\nu}$.
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

    /// Evaluate the multi-linear at some query $(r_0, ..., r_{{\nu} - 1}) \in \mathbb{F}^{\nu}$.
    ///
    /// It first computes the evaluations of the Lagrange basis polynomials over the interpolating
    /// set ${0 , 1}^{\nu}$ at $(r_0, ..., r_{{\nu} - 1})$ i.e., the Lagrange kernel at $(r_0, ..., r_{{\nu} - 1})$.
    /// The evaluation then is the inner product, indexed by ${0 , 1}^{\nu}$, of the vector of
    /// evaluations times the Lagrange kernel.
    pub fn evaluate(&self, query: &[E]) -> E {
        let tensored_query = compute_lagrange_basis_evals_at(query);
        inner_product(&self.evaluations, &tensored_query)
    }

    /// Similar to [`Self::evaluate`], except that the query was already turned into the Lagrange
    /// kernel (i.e. the [`lagrange_ker::EqFunction`] evaluated at every point in the set
    /// `${0 , 1}^{\nu}$`).
    ///
    /// This is more efficient than [`Self::evaluate`] when multiple different [`MultiLinearPoly`]
    /// need to be evaluated at the same query point.
    pub fn evaluate_with_lagrange_kernel(&self, lagrange_kernel: &[E]) -> E {
        inner_product(&self.evaluations, lagrange_kernel)
    }

    /// Computes $f(r_0, y_1, ..., y_{{\nu} - 1})$ using the linear interpolation formula
    /// $(1 - r_0) * f(0, y_1, ..., y_{{\nu} - 1}) + r_0 * f(1, y_1, ..., y_{{\nu} - 1})$ and assigns
    /// the resulting multi-linear, defined over a domain of half the size, to `self`.
    pub fn bind_least_significant_variable(&mut self, round_challenge: E) {
        let num_evals = self.evaluations.len() >> 1;
        #[cfg(not(feature = "concurrent"))]
        {
            for i in 0..num_evals {
                // SAFETY: This loops over [0, evaluations.len()/2). The largest value for `i` is
                // `(evaluations.len() / 2) - 1`. Hence, the largest value for `(i<<1)` is
                // `evaluations.len() - 2`, and largest value for `(i<<1) + 1` is `evaluations.len() - 1`.
                let evaluations_2i = unsafe { *self.evaluations.get_unchecked(i << 1) };
                let evaluations_2i_plus_1 = unsafe { *self.evaluations.get_unchecked((i << 1) + 1) };

                self.evaluations[i] =
                    evaluations_2i + round_challenge * (evaluations_2i_plus_1 - evaluations_2i);
            }
            self.evaluations.truncate(num_evals);
        }

        #[cfg(feature = "concurrent")]
        {
            let mut result = unsafe { utils::uninit_vector(num_evals) };
            result.par_iter_mut().enumerate().for_each(|(i, ev)| {
                *ev = self.evaluations[i << 1]
                    + round_challenge * (self.evaluations[(i << 1) + 1] - self.evaluations[i << 1])
            });
            self.evaluations = result
        }
    }

    /// Given the multilinear polynomial $f(y_0, y_1, ..., y_{{\nu} - 1})$, returns two polynomials:
    /// $f(0, y_1, ..., y_{{\nu} - 1})$ and $f(1, y_1, ..., y_{{\nu} - 1})$.
    pub fn project_least_significant_variable(mut self) -> (Self, Self) {
        let odds: Vec<E> = self
            .evaluations
            .iter()
            .enumerate()
            .filter_map(|(idx, x)| if idx % 2 == 1 { Some(*x) } else { None })
            .collect();

        // Builds the evens multilinear from the current `self.evaluations` buffer, which saves an
        // allocation.
        let evens = {
            let evens_size = self.num_evaluations() / 2;
            for write_idx in 0..evens_size {
                let read_idx = write_idx * 2;
                self.evaluations[write_idx] = self.evaluations[read_idx];
            }
            self.evaluations.truncate(evens_size);

            self.evaluations
        };

        (Self::from_evaluations(evens), Self::from_evaluations(odds))
    }
}

impl<E: FieldElement> Index<usize> for MultiLinearPoly<E> {
    type Output = E;

    fn index(&self, index: usize) -> &E {
        &(self.evaluations[index])
    }
}

impl<E> Serializable for MultiLinearPoly<E>
where
    E: FieldElement,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { evaluations } = self;
        evaluations.write_into(target);
    }
}

impl<E> Deserializable for MultiLinearPoly<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self {
            evaluations: Deserializable::read_from(source)?,
        })
    }
}

// EQ FUNCTION
// ================================================================================================

/// Maximal expected size of the point of a given Lagrange kernel.
const MAX_EQ_SIZE: usize = 25;

/// The EQ (equality) function is the binary function defined by
///
/// $$
/// EQ:    {0 , 1}^{\nu} ⛌ {0 , 1}^{\nu} \longrightarrow {0 , 1}
///   ((x_0, ..., x_{{\nu} - 1}), (y_0, ..., y_{{\nu} - 1})) \mapsto \prod_{i = 0}^{{\nu} - 1} (x_i \cdot y_i + (1 - x_i)
/// \cdot (1 - y_i))
/// $$
///
/// Taking its multi-linear extension $\tilde{EQ}$, we can define a basis for the set of multi-linear
/// polynomials in {\nu} variables by
///         $${\tilde{EQ}(., (y_0, ..., y_{{\nu} - 1})): (y_0, ..., y_{{\nu} - 1}) \in {0 , 1}^{\nu}}$$
/// where each basis function is a function of its first argument. This is called the Lagrange or
/// evaluation basis for evaluation set ${0 , 1}^{\nu}$.
///
/// Given a function $(f: {0 , 1}^{\nu} \longrightarrow \mathbb{F})$, its multi-linear extension (i.e., the unique
/// mult-linear polynomial extending `f` to $(\tilde{f}: \mathbb{F}^{\nu} \longrightarrow \mathbb{F})$ and agreeing with it on ${0 , 1}^{\nu}$) is
/// defined as the summation of the evaluations of f against the Lagrange basis.
/// More specifically, given $(r_0, ..., r_{{\nu} - 1}) \in \mathbb{F}^{\nu}$, then:
///
/// $$
///     \tilde{f}(r_0, ..., r_{{\nu} - 1}) = \sum_{(y_0, ..., y_{{\nu} - 1}) \in {0 , 1}^{\nu}}
///                  f(y_0, ..., y_{{\nu} - 1}) \tilde{EQ}((r_0, ..., r_{{\nu} - 1}), (y_0, ..., y_{{\nu} - 1}))
/// $$
///
/// We call the Lagrange kernel the evaluation of the $\tilde{EQ}$ function at
/// $((r_0, ..., r_{{\nu} - 1}), (y_0, ..., y_{{\nu} - 1}))$ for all $(y_0, ..., y_{{\nu} - 1}) \in {0 , 1}^{\nu}$ for
/// a fixed $(r_0, ..., r_{{\nu} - 1}) \in \mathbb{F}^{\nu}$.
///
/// [`EqFunction`] represents $\tilde{EQ}$ the multi-linear extension of
///
/// $((y_0, ..., y_{{\nu} - 1}) \mapsto EQ((r_0, ..., r_{{\nu} - 1}), (y_0, ..., y_{{\nu} - 1})))$
///
/// and contains a method to generate the Lagrange kernel for defining evaluations of multi-linear
/// extensions of arbitrary functions $(f: {0 , 1}^{\nu} \longrightarrow \mathbb{F})$ at a given point $(r_0, ..., r_{{\nu} - 1})$
/// as well as a method to evaluate $\tilde{EQ}((r_0, ..., r_{{\nu} - 1}), (t_0, ..., t_{{\nu} - 1})))$ for
/// $(t_0, ..., t_{{\nu} - 1}) \in \mathbb{F}^{\nu}$.
pub struct EqFunction<E> {
    r: SmallVec<[E; MAX_EQ_SIZE]>,
}

impl<E: FieldElement> EqFunction<E> {
    /// Creates a new [EqFunction].
    pub fn new(r: SmallVec<[E; MAX_EQ_SIZE]>) -> Self {
        EqFunction { r }
    }

    /// Computes $\tilde{EQ}((r_0, ..., r_{{\nu} - 1}), (t_0, ..., t_{{\nu} - 1})))$.
    pub fn evaluate(&self, t: &[E]) -> E {
        assert_eq!(self.r.len(), t.len());

        (0..self.r.len())
            .map(|i| self.r[i] * t[i] + (E::ONE - self.r[i]) * (E::ONE - t[i]))
            .fold(E::ONE, |acc, term| acc * term)
    }

    /// Computes $\tilde{EQ}((r_0, ..., r_{{\nu} - 1}), (y_0, ..., y_{{\nu} - 1}))$ for all
    /// $(y_0, ..., y_{{\nu} - 1}) \in {0 , 1}^{\nu}$ i.e., the Lagrange kernel at $r = (r_0, ..., r_{{\nu} - 1})$.
    pub fn evaluations(&self) -> Vec<E> {
        compute_lagrange_basis_evals_at(&self.r)
    }

    /// Returns the evaluations of
    /// $((y_0, ..., y_{{\nu} - 1}) \mapsto \tilde{EQ}((r_0, ..., r_{{\nu} - 1}), (y_0, ..., y_{{\nu} - 1})))$
    /// over ${0 , 1}^{\nu}$.
    pub fn ml_at(evaluation_point: SmallVec<[E; MAX_EQ_SIZE]>) -> MultiLinearPoly<E> {
        let eq_evals = EqFunction::new(evaluation_point).evaluations();
        MultiLinearPoly::from_evaluations(eq_evals)
    }
}

// HELPER
// ================================================================================================

/// Computes the evaluations of the Lagrange basis polynomials over the interpolating
/// set ${0 , 1}^{\nu}$ at $(r_0, ..., r_{{\nu} - 1})$ i.e., the Lagrange kernel at $(r_0, ..., r_{{\nu} - 1})$.
///
/// If `concurrent` feature is enabled, this function can make use of multi-threading.
///
/// The implementation uses the memoization technique in Lemma 3.8 in [1]. More precisely, we can
/// build a table $A^{(\nu)}$ in $\nu$ steps using the following master equation:
///
/// $$
/// A^{(j)}\left[\left(w_{1}, \dots, w_{j} \right)\right] =
/// A^{(j - 1)}\left[\left(w_{1}, \dots, w_{j - 1} \right)\right] \times
/// \left(w_{j}\cdot r_{j} + (1 - w_{j})\cdot( 1 - r_{j}) \right)
/// $$
///  
/// if we interpret $\left(w_{1}, \dots, w_{j} \right)$ in little endian i.e.,
/// $\left(w_{1}, \dots, w_{j} \right) = \sum_{i=1}^{\nu} 2^{i - 1}\cdot w_{i}$.
///
/// We thus have the following algorithm:
///
/// 1. Split current table, stored as a vector, $A^{(j)}\left[\left(w_{1}, \dots, w_{j} \right)\right]$
///    into two tables $A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 0 \right)\right]$ and
///    $A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 1 \right)\right]$,
///    with the first part initialized to $A^{(j - 1)}\left[\left(w_{1}, \dots, w_{j-1} \right)\right]$.
/// 2. Iterating over $\left(w_{1}, \dots, w_{j-1} \right)$, do:
///     1. Let $factor = A^{(j - 1)}\left[\left(w_{1}, \dots, w_{j-1} \right)\right]$, which is equal
///        by the above to $A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 0 \right)\right]$.
///     2. $A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 1 \right)\right] = factor \cdot r_j$
///     3. $A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 0 \right)\right] =
///         A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 0 \right)\right] -
///         A^{(j)}\left[\left(w_{1}, \dots, w_{j-1}, 1 \right)\right]$
///
/// Note that we can allocate from the start a vector of size $2^{\nu}$ in order to hold the final
/// as well as the intermediate tables.
///
/// [1]: https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf
fn compute_lagrange_basis_evals_at<E: FieldElement>(query: &[E]) -> Vec<E> {
    let n = 1 << query.len();
    let mut evals = unsafe { utils::uninit_vector(n) };

    let mut size = 1;
    evals[0] = E::ONE;
    #[cfg(not(feature = "concurrent"))]
    let evals = {
        for r_i in query.iter() {
            let (left_evals, right_evals) = evals.split_at_mut(size);
            left_evals.iter_mut().zip(right_evals.iter_mut()).for_each(|(left, right)| {
                let factor = *left;
                *right = factor * *r_i;
                *left -= *right;
            });

            size <<= 1;
        }
        evals
    };

    #[cfg(feature = "concurrent")]
    let evals = {
        for r_i in query.iter() {
            let (left_evals, right_evals) = evals.split_at_mut(size);
            left_evals
                .par_iter_mut()
                .zip(right_evals.par_iter_mut())
                .for_each(|(left, right)| {
                    let factor = *left;
                    *right = factor * *r_i;
                    *left -= *right;
                });

            size <<= 1;
        }
        evals
    };

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
    use smallvec::smallvec;

    let one = BaseElement::ONE;

    // Lagrange kernel is computed correctly
    let r0 = rand_value();
    let r1 = rand_value();
    let eq_function = EqFunction::new(smallvec![r0, r1]);

    let expected = vec![(one - r0) * (one - r1), r0 * (one - r1), (one - r0) * r1, r0 * r1];

    assert_eq!(expected, eq_function.evaluations());

    // Lagrange kernel evaluation is correct
    let q0 = rand_value();
    let q1 = rand_value();
    let tensored_query = vec![(one - q0) * (one - q1), q0 * (one - q1), (one - q0) * q1, q0 * q1];

    let expected = inner_product(&tensored_query, &eq_function.evaluations());

    assert_eq!(expected, eq_function.evaluate(&[q0, q1]))
}
