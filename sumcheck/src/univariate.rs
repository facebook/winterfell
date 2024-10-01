// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use math::{batch_inversion, polynom, FieldElement};
use smallvec::SmallVec;
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// CONSTANTS
// ================================================================================================

/// Maximum expected size of the round polynomials. This is needed for `SmallVec`. The size of
/// the round polynomials is dictated by the degree of the non-linearity in the sum-check statement
/// which is direcly influenced by the maximal degrees of the numerators and denominators appearing
/// in the LogUp-GKR relation and equal to one plus the maximal degree of the numerators and
/// maximal degree of denominators.
/// The following value assumes that this degree is at most 10.
const MAX_POLY_SIZE: usize = 10;

// COMPRESSED UNIVARIATE POLYNOMIAL
// ================================================================================================

/// The coefficients of a univariate polynomial of degree n with the linear term coefficient
/// omitted.
///
/// This compressed representation is useful during the sum-check protocol as the full uncompressed
/// representation can be recovered from the compressed one and the current sum-check round claim.
#[derive(Clone, Debug, PartialEq)]
pub struct CompressedUnivariatePoly<E: FieldElement>(pub(crate) SmallVec<[E; MAX_POLY_SIZE]>);

impl<E: FieldElement> CompressedUnivariatePoly<E> {
    /// Evaluates a polynomial at a challenge point using a round claim.
    ///
    /// The round claim is used to recover the coefficient of the linear term using the relation
    /// 2 * c0 + c1 + ... c_{n - 1} = claim. Using the complete list of coefficients, the polynomial
    /// is then evaluated using Horner's method.
    pub fn evaluate_using_claim(&self, claim: &E, challenge: &E) -> E {
        // recover the coefficient of the linear term
        let c1 = *claim - self.0.iter().fold(E::ZERO, |acc, term| acc + *term) - self.0[0];

        // construct the full coefficient list
        let mut complete_coefficients = vec![self.0[0], c1];
        complete_coefficients.extend_from_slice(&self.0[1..]);

        // evaluate
        polynom::eval(&complete_coefficients, *challenge)
    }

    /// Given the evaluations of a polynomial over the set $0, 1, \cdots, d - 1$ and a `root` not in
    /// the interpolation set, computes its coefficients.
    pub fn interpolate_equidistant_points(ys: &[E], root: E) -> CompressedUnivariatePoly<E> {
        // we factor out the term `(x - r)` where `r` is the root
        let quotient: Vec<E> = (0..ys.len()).map(|i| E::from(i as u32) - root).collect();
        let quotient_inv = batch_inversion(&quotient);
        let mut ys: Vec<E> = ys.iter().zip(quotient_inv.iter()).map(|(&y, &q)| y * q).collect();

        // the zeroth coefficient can be recovered immediately
        let c0 = ys.remove(0);

        // build the interpolation set
        let n_minus_1 = ys.len();
        let points = (1..=n_minus_1 as u32).map(E::BaseField::from).collect::<Vec<_>>();

        // construct their inverses. These will be needed for computing the evaluations
        // of the q polynomial as well as for doing the interpolation on q where q is
        // defined as $p(x) = c0 + x * q(x) where q(x) = c1 + ... + c_{n-1} * x^{n - 2}$
        let points_inv = batch_inversion(&points);

        // compute the evaluations of q
        let q_evals: Vec<E> = ys
            .iter()
            .enumerate()
            .map(|(i, evals)| (*evals - c0).mul_base(points_inv[i]))
            .collect();

        // interpolate q
        let q_coefs = multiply_by_inverse_vandermonde(&q_evals, &points_inv);

        // append c0 to the coefficients of q to get the coefficients of p. The linear term
        // coefficient is removed as this can be recovered from the other coefficients using
        // the reduced claim.
        let mut coefficients = SmallVec::<[E; MAX_POLY_SIZE]>::with_capacity(ys.len() + 1);
        coefficients.push(c0);
        coefficients.extend_from_slice(&q_coefs[..]);

        // multiply back the factor `(x - r)`
        let mut p_coefficients = polynom::mul(&coefficients, &[-root, E::ONE]);

        // remove the linear factor as it can be recovered from the `claim` and the other factors
        p_coefficients.remove(1);

        CompressedUnivariatePoly(p_coefficients.into())
    }
}

impl<E: FieldElement> Serializable for CompressedUnivariatePoly<E> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let vector: Vec<E> = self.0.clone().into_vec();
        vector.write_into(target);
    }
}

impl<E> Deserializable for CompressedUnivariatePoly<E>
where
    E: FieldElement,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let vector: Vec<E> = Vec::<E>::read_from(source)?;
        Ok(Self(vector.into()))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Given a (row) vector `v`, computes the vector-matrix product `v * V^{-1}` where `V` is
/// the Vandermonde matrix over the points `1, ..., n` where `n` is the length of `v`.
/// The resulting vector will then be the coefficients of the minimal interpolating polynomial
/// through the points `(i+1, v[i])` for `i` in `0, ..., n - 1`
///
/// The naive way would be to invert the matrix `V` and then compute the vector-matrix product
/// this will cost `O(n^3)` operations and `O(n^2)` memory. We can also try Gaussian elimination
/// but this is also worst case `O(n^3)` operations and `O(n^2)` memory.
/// In the following implementation, we use the fact that the points over which we are interpolating
/// is a set of equidistant points and thus both the Vandermonde matrix and its inverse can be
/// described by sparse linear recurrence equations.
/// More specifically, we use the representation given in [1], where `V^{-1}` is represented as
/// `U * M` where:
///
/// 1. `M` is a lower triangular matrix where its entries are given by M(i, j) = M(i - 1, j) - M(i -
///    1, j - 1) / (i - 1) with boundary conditions M(i, 1) = 1 and M(i, j) = 0 when j > i.
///
/// 2. `U` is an upper triangular (involutory) matrix where its entries are given by U(i, j) = U(i,
///    j - 1) - U(i - 1, j - 1) with boundary condition U(1, j) = 1 and U(i, j) = 0 when i > j.
///
/// Note that the matrix indexing in the formulas above matches the one in the reference and starts
/// from 1.
///
/// The above implies that we can do the vector-matrix multiplication in `O(n^2)` and using only
/// `O(n)` space.
///
/// [1]: https://link.springer.com/article/10.1007/s002110050360
fn multiply_by_inverse_vandermonde<E: FieldElement>(
    vector: &[E],
    nodes_inv: &[E::BaseField],
) -> Vec<E> {
    let res = multiply_by_u(vector);
    multiply_by_m(&res, nodes_inv)
}

/// Multiplies a (row) vector `v` by an upper triangular matrix `U` to compute `v * U`.
///
/// `U` is an upper triangular (involutory) matrix with its entries given by
///     U(i, j) = U(i, j - 1) - U(i - 1, j - 1)
/// with boundary condition U(1, j) = 1 and U(i, j) = 0 when i > j.
fn multiply_by_u<E: FieldElement>(vector: &[E]) -> Vec<E> {
    let n = vector.len();
    let mut previous_u_col = vec![E::BaseField::ZERO; n];
    previous_u_col[0] = E::BaseField::ONE;
    let mut current_u_col = vec![E::BaseField::ZERO; n];
    current_u_col[0] = E::BaseField::ONE;

    let mut result: Vec<E> = vec![E::ZERO; n];
    for (i, res) in result.iter_mut().enumerate() {
        *res = vector[0];

        for (j, v) in vector.iter().enumerate().take(i + 1).skip(1) {
            let u_entry: E::BaseField =
                compute_u_entry::<E>(j, &mut previous_u_col, &mut current_u_col);
            *res += v.mul_base(u_entry);
        }
        previous_u_col.clone_from(&current_u_col);
    }

    result
}

/// Multiplies a (row) vector `v` by a lower triangular matrix `M` to compute `v * M`.
///
/// `M` is a lower triangular matrix with its entries given by
///     M(i, j) = M(i - 1, j) - M(i - 1, j - 1) / (i - 1)
/// with boundary conditions M(i, 1) = 1 and M(i, j) = 0 when j > i.
fn multiply_by_m<E: FieldElement>(vector: &[E], nodes_inv: &[E::BaseField]) -> Vec<E> {
    let n = vector.len();
    let mut previous_m_col = vec![E::BaseField::ONE; n];
    let mut current_m_col = vec![E::BaseField::ZERO; n];
    current_m_col[0] = E::BaseField::ONE;

    let mut result: Vec<E> = vec![E::ZERO; n];
    result[0] = vector.iter().fold(E::ZERO, |acc, term| acc + *term);
    for (i, res) in result.iter_mut().enumerate().skip(1) {
        current_m_col = vec![E::BaseField::ZERO; n];

        for (j, v) in vector.iter().enumerate().skip(i) {
            let m_entry: E::BaseField =
                compute_m_entry::<E>(j, &mut previous_m_col, &mut current_m_col, nodes_inv[j - 1]);
            *res += v.mul_base(m_entry);
        }
        previous_m_col.clone_from(&current_m_col);
    }

    result
}

/// Returns the j-th entry of the i-th column of matrix `U` given the values of the (i - 1)-th
/// column. The i-th column is also updated with the just computed `U(i, j)` entry.
///
/// `U` is an upper triangular (involutory) matrix with its entries given by
///     U(i, j) = U(i, j - 1) - U(i - 1, j - 1)
/// with boundary condition U(1, j) = 1 and U(i, j) = 0 when i > j.
fn compute_u_entry<E: FieldElement>(
    j: usize,
    col_prev: &mut [E::BaseField],
    col_cur: &mut [E::BaseField],
) -> E::BaseField {
    let value = col_prev[j] - col_prev[j - 1];
    col_cur[j] = value;
    value
}

/// Returns the j-th entry of the i-th column of matrix `M` given the values of the (i - 1)-th
/// and the i-th columns. The i-th column is also updated with the just computed `M(i, j)` entry.
///
/// `M` is a lower triangular matrix with its entries given by
///     M(i, j) = M(i - 1, j) - M(i - 1, j - 1) / (i - 1)
/// with boundary conditions M(i, 1) = 1 and M(i, j) = 0 when j > i.
fn compute_m_entry<E: FieldElement>(
    j: usize,
    col_previous: &mut [E::BaseField],
    col_current: &mut [E::BaseField],
    node_inv: E::BaseField,
) -> E::BaseField {
    let value = col_current[j - 1] - node_inv * col_previous[j - 1];
    col_current[j] = value;
    value
}

// TESTS
// ================================================================================================

#[test]
fn test_poly_partial() {
    use math::fields::f64::BaseElement;

    let degree = 1000;

    // compute the claim
    let p: Vec<BaseElement> = rand_utils::rand_vector(degree);
    let evals = polynom::eval_many(&p, &[BaseElement::ZERO, BaseElement::ONE]);
    let claim = evals[0] + evals[1];

    // build compressed polynomial
    let mut poly_coeff = p.clone();
    poly_coeff.remove(1);
    let poly_coeff = CompressedUnivariatePoly(poly_coeff.into());

    // generate random challenge
    let r = rand_utils::rand_vector(1);

    assert_eq!(polynom::eval(&p, r[0]), poly_coeff.evaluate_using_claim(&claim, &r[0]))
}

#[test]
fn test_serialization() {
    use math::fields::f64::BaseElement;

    let original_poly =
        CompressedUnivariatePoly(rand_utils::rand_array::<BaseElement, MAX_POLY_SIZE>().into());
    let poly_bytes = original_poly.to_bytes();

    let deserialized_poly =
        CompressedUnivariatePoly::<BaseElement>::read_from_bytes(&poly_bytes).unwrap();

    assert_eq!(original_poly, deserialized_poly)
}
