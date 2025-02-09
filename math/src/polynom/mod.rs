// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Basic polynomial operations.
//!
//! This module provides a set of function for basic polynomial operations, including:
//! - Polynomial evaluation using Horner method.
//! - Polynomial interpolation using Lagrange method.
//! - Polynomial addition, subtraction, multiplication, and division.
//! - Synthetic polynomial division for efficient division by polynomials of the form `x`^`a` - `b`.
//!
//! In the context of this module any slice of field elements is considered to be a polynomial
//! in reverse coefficient form. A few examples:
//!
//! ```
//! # use winter_math::{fields::{f128::BaseElement}, FieldElement};
//! // p(x) = 2 * x + 1
//! let p = vec![BaseElement::new(1), BaseElement::new(2)];
//!
//! // p(x) = 4 * x^2 + 3
//! let p = [BaseElement::new(3), BaseElement::ZERO, BaseElement::new(4)];
//! ```

use alloc::vec::Vec;
use core::mem;

use utils::group_slice_elements;

use crate::{field::FieldElement, utils::batch_inversion};

#[cfg(test)]
mod tests;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates a polynomial at a single point and returns the result.
///
/// Evaluates polynomial `p` at coordinate `x` using
/// [Horner's method](https://en.wikipedia.org/wiki/Horner%27s_method).
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // define polynomial: f(x) = 3 * x^2 + 2 * x + 1
/// let p = (1u32..4).map(BaseElement::from).collect::<Vec<_>>();
///
/// // evaluate the polynomial at point 4
/// let x = BaseElement::new(4);
/// assert_eq!(BaseElement::new(57), eval(&p, x));
/// ```
pub fn eval<B, E>(p: &[B], x: E) -> E
where
    B: FieldElement,
    E: FieldElement + From<B>,
{
    // Horner evaluation
    p.iter().rev().fold(E::ZERO, |acc, &coeff| acc * x + E::from(coeff))
}

/// Evaluates a polynomial at multiple points and returns a vector of results.
///
/// Evaluates polynomial `p` at all coordinates in `xs` slice by repeatedly invoking
/// `polynom::eval()` function.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // define polynomial: f(x) = 3 * x^2 + 2 * x + 1
/// let p = (1_u32..4).map(BaseElement::from).collect::<Vec<_>>();
/// let xs = (3_u32..6).map(BaseElement::from).collect::<Vec<_>>();
///
/// let expected = xs.iter().map(|x| eval(&p, *x)).collect::<Vec<_>>();
/// assert_eq!(expected, eval_many(&p, &xs));
/// ```
pub fn eval_many<B, E>(p: &[B], xs: &[E]) -> Vec<E>
where
    B: FieldElement,
    E: FieldElement + From<B>,
{
    xs.iter().map(|x| eval(p, *x)).collect()
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Returns a polynomial in coefficient form interpolated from a set of X and Y coordinates.
///
/// Uses [Lagrange interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial) to build a
/// polynomial from X and Y coordinates. If `remove_leading_zeros = true`, all leading coefficients
/// which are ZEROs will be truncated; otherwise, the length of result will be equal to the number
/// of X coordinates.
///
/// # Panics
/// Panics if number of X and Y coordinates is not the same.
///
/// # Example
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// # use rand_utils::rand_vector;
/// let xs: Vec<BaseElement> = rand_vector(16);
/// let ys: Vec<BaseElement> = rand_vector(16);
///
/// let p = interpolate(&xs, &ys, false);
/// assert_eq!(ys, eval_many(&p, &xs));
/// ```
pub fn interpolate<E>(xs: &[E], ys: &[E], remove_leading_zeros: bool) -> Vec<E>
where
    E: FieldElement,
{
    debug_assert!(xs.len() == ys.len(), "number of X and Y coordinates must be the same");

    let roots = poly_from_roots(xs);
    let numerators: Vec<Vec<E>> = xs.iter().map(|&x| syn_div(&roots, 1, x)).collect();

    let denominators: Vec<E> = numerators.iter().zip(xs).map(|(e, &x)| eval(e, x)).collect();
    let denominators = batch_inversion(&denominators);

    let mut result = vec![E::ZERO; xs.len()];
    for i in 0..xs.len() {
        let y_slice = ys[i] * denominators[i];
        for (j, res) in result.iter_mut().enumerate() {
            *res += numerators[i][j] * y_slice;
        }
    }

    if remove_leading_zeros {
        crate::polynom::remove_leading_zeros(&result)
    } else {
        result
    }
}

/// Returns a vector of polynomials interpolated from the provided X and Y coordinate batches.
///
/// Uses [Lagrange interpolation](https://en.wikipedia.org/wiki/Lagrange_polynomial) to build a
/// vector of polynomial from X and Y coordinate batches (one polynomial per batch).
///
/// When the number of batches is larger, this function is significantly faster than using
/// `polynom::interpolate()` function individually for each batch of coordinates. The speed-up
/// is primarily due to computing all inversions as a single batch inversion across all
/// coordinate batches.
///
/// # Panics
/// Panics if the number of X coordinate batches and Y coordinate batches is not the same.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// # use rand_utils::rand_array;
/// let x_batches: Vec<[BaseElement; 8]> = vec![rand_array(), rand_array()];
/// let y_batches: Vec<[BaseElement; 8]> = vec![rand_array(), rand_array()];
///
/// let polys = interpolate_batch(&x_batches, &y_batches);
/// for ((p, xs), ys) in polys.iter().zip(x_batches).zip(y_batches) {
///     assert_eq!(ys.to_vec(), eval_many(p, &xs));
/// }
/// ```
pub fn interpolate_batch<E, const N: usize>(xs: &[[E; N]], ys: &[[E; N]]) -> Vec<[E; N]>
where
    E: FieldElement,
{
    debug_assert!(
        xs.len() == ys.len(),
        "number of X coordinate batches and Y coordinate batches must be the same"
    );

    let n = xs.len();
    let mut equations = vec![[E::ZERO; N]; n * N];
    let mut inverses = vec![E::ZERO; n * N];

    // TODO: converting this to an array results in about 5% speed-up, but unfortunately, complex
    // generic constraints are not yet supported: https://github.com/rust-lang/rust/issues/76560
    let mut roots = vec![E::ZERO; N + 1];

    for (i, xs) in xs.iter().enumerate() {
        fill_zero_roots(xs, &mut roots);
        for (j, &x) in xs.iter().enumerate() {
            let equation = &mut equations[i * N + j];
            // optimized synthetic division for this context
            equation[N - 1] = roots[N];
            for k in (0..N - 1).rev() {
                equation[k] = roots[k + 1] + equation[k + 1] * x;
            }
            inverses[i * N + j] = eval(equation, x);
        }
    }
    let equations = group_slice_elements::<[E; N], N>(&equations);
    let inverses_vec = batch_inversion(&inverses);
    let inverses = group_slice_elements::<E, N>(&inverses_vec);

    let mut result = vec![[E::ZERO; N]; n];
    for (i, poly) in result.iter_mut().enumerate() {
        for j in 0..N {
            let inv_y = ys[i][j] * inverses[i][j];
            for (res_coeff, &eq_coeff) in poly.iter_mut().zip(equations[i][j].iter()) {
                *res_coeff += eq_coeff * inv_y;
            }
        }
    }

    result
}

// POLYNOMIAL MATH OPERATIONS
// ================================================================================================

/// Returns a polynomial resulting from adding two polynomials together.
///
/// Polynomials `a` and `b` are expected to be in the coefficient form, and the returned
/// polynomial will be in the coefficient form as well. The length of the returned vector
/// will be max(a.len(), b.len()).
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p1(x) = 4 * x^2 + 3 * x + 2
/// let p1 = (2_u32..5).map(BaseElement::from).collect::<Vec<_>>();
/// // p2(x) = 2 * x + 1
/// let p2 = (1_u32..3).map(BaseElement::from).collect::<Vec<_>>();
///
/// // expected result = 4 * x^2 + 5 * x + 3
/// let expected = vec![BaseElement::new(3), BaseElement::new(5), BaseElement::new(4)];
/// assert_eq!(expected, add(&p1, &p2));
/// ```
pub fn add<E>(a: &[E], b: &[E]) -> Vec<E>
where
    E: FieldElement,
{
    let result_len = core::cmp::max(a.len(), b.len());
    let mut result = Vec::with_capacity(result_len);
    for i in 0..result_len {
        let c1 = if i < a.len() { a[i] } else { E::ZERO };
        let c2 = if i < b.len() { b[i] } else { E::ZERO };
        result.push(c1 + c2);
    }
    result
}

/// Returns a polynomial resulting from subtracting one polynomial from another.
///
/// Specifically, subtracts polynomial `b` from polynomial `a` and returns the result. Both
/// polynomials are expected to be in the coefficient form, and the returned polynomial will
/// be in the coefficient form as well.  The length of the returned vector will be
/// max(a.len(), b.len()).
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p1(x) = 4 * x^2 + 3 * x + 2
/// let p1 = (2_u32..5).map(BaseElement::from).collect::<Vec<_>>();
/// // p2(x) = 2 * x + 1
/// let p2 = (1_u32..3).map(BaseElement::from).collect::<Vec<_>>();
///
/// // expected result = 4 * x^2 + x + 1
/// let expected = vec![BaseElement::new(1), BaseElement::new(1), BaseElement::new(4)];
/// assert_eq!(expected, sub(&p1, &p2));
/// ```
pub fn sub<E>(a: &[E], b: &[E]) -> Vec<E>
where
    E: FieldElement,
{
    let result_len = core::cmp::max(a.len(), b.len());
    let mut result = Vec::with_capacity(result_len);
    for i in 0..result_len {
        let c1 = if i < a.len() { a[i] } else { E::ZERO };
        let c2 = if i < b.len() { b[i] } else { E::ZERO };
        result.push(c1 - c2);
    }
    result
}

/// Returns a polynomial resulting from multiplying two polynomials together.
///
/// Polynomials `a` and `b` are expected to be in the coefficient form, and the returned
/// polynomial will be in the coefficient form as well. The length of the returned vector
/// will be a.len() + b.len() - 1.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p1(x) = x + 1
/// let p1 = [BaseElement::ONE, BaseElement::ONE];
/// // p2(x) = x^2 + 2
/// let p2 = [BaseElement::new(2), BaseElement::ZERO, BaseElement::ONE];
///
/// // expected result = x^3 + x^2 + 2 * x + 2
/// let expected = vec![
///     BaseElement::new(2),
///     BaseElement::new(2),
///     BaseElement::new(1),
///     BaseElement::new(1),
/// ];
/// assert_eq!(expected, mul(&p1, &p2));
/// ```
pub fn mul<E>(a: &[E], b: &[E]) -> Vec<E>
where
    E: FieldElement,
{
    let result_len = a.len() + b.len() - 1;
    let mut result = vec![E::ZERO; result_len];
    for i in 0..a.len() {
        for j in 0..b.len() {
            let s = a[i] * b[j];
            result[i + j] += s;
        }
    }
    result
}

/// Returns a polynomial resulting from multiplying a given polynomial by a scalar value.
///
/// Specifically, multiplies every coefficient of polynomial `p` by constant `k` and returns
/// the resulting vector.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// let p = [BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)];
/// let k = BaseElement::new(2);
///
/// let expected = vec![BaseElement::new(2), BaseElement::new(4), BaseElement::new(6)];
/// assert_eq!(expected, mul_by_scalar(&p, k));
/// ```
pub fn mul_by_scalar<E>(p: &[E], k: E) -> Vec<E>
where
    E: FieldElement,
{
    let mut result = Vec::with_capacity(p.len());
    for coeff in p {
        result.push(*coeff * k);
    }
    result
}

/// Returns a polynomial resulting from dividing one polynomial by another.
///
/// Specifically, divides polynomial `a` by polynomial `b` and returns the result. If the
/// polynomials don't divide evenly, the remainder is ignored. Both polynomials are expected to
/// be in the coefficient form, and the returned polynomial will be in the coefficient form as
/// well. The length of the returned vector will be a.len() - b.len() + 1.
///
/// # Panics
/// Panics if:
/// * Polynomial `b` is empty.
/// * Degree of polynomial `b` is zero and the constant coefficient is ZERO.
/// * The degree of polynomial `b` is greater than the degree of polynomial `a`.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p1(x) = x^3 + x^2 + 2 * x + 2
/// let p1 = [
///     BaseElement::new(2),
///     BaseElement::new(2),
///     BaseElement::new(1),
///     BaseElement::new(1),
/// ];
/// // p2(x) = x^2 + 2
/// let p2 = [BaseElement::new(2), BaseElement::ZERO, BaseElement::ONE];
///
/// // expected result = x + 1
/// let expected = vec![BaseElement::ONE, BaseElement::ONE];
/// assert_eq!(expected, div(&p1, &p2));
/// ```
pub fn div<E>(a: &[E], b: &[E]) -> Vec<E>
where
    E: FieldElement,
{
    let mut apos = degree_of(a);
    let mut a = a.to_vec();

    let bpos = degree_of(b);
    assert!(apos >= bpos, "cannot divide by polynomial of higher degree");
    if bpos == 0 {
        assert!(!b.is_empty(), "cannot divide by empty polynomial");
        assert!(b[0] != E::ZERO, "cannot divide polynomial by zero");
    }

    let mut result = vec![E::ZERO; apos - bpos + 1];
    for i in (0..result.len()).rev() {
        let quot = a[apos] / b[bpos];
        result[i] = quot;
        for j in (0..bpos).rev() {
            a[i + j] -= b[j] * quot;
        }
        apos = apos.wrapping_sub(1);
    }

    result
}

/// Returns a polynomial resulting from dividing a polynomial by a polynomial of special form.
///
/// Specifically, divides polynomial `p` by polynomial (x^`a` - `b`) using
/// [synthetic division](https://en.wikipedia.org/wiki/Synthetic_division) method; if the
/// polynomials don't divide evenly, the remainder is ignored. Polynomial `p` is expected
/// to be in the coefficient form, and the result will be in the coefficient form as well.
/// The length of the resulting polynomial will be equal to `p.len()`.
///
/// This function is significantly faster than the generic `polynom::div()` function.
///
/// # Panics
/// Panics if:
/// * `a` is zero;
/// * `b` is zero;
/// * `p.len()` is smaller than or equal to `a`.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p(x) = x^3 + x^2 + 2 * x + 2
/// let p = [
///     BaseElement::new(2),
///     BaseElement::new(2),
///     BaseElement::new(1),
///     BaseElement::new(1),
/// ];
///
/// // expected result = x^2 + 2
/// let expected =
///     vec![BaseElement::new(2), BaseElement::ZERO, BaseElement::new(1), BaseElement::ZERO];
///
/// // divide by x + 1
/// assert_eq!(expected, syn_div(&p, 1, -BaseElement::ONE));
/// ```
pub fn syn_div<E>(p: &[E], a: usize, b: E) -> Vec<E>
where
    E: FieldElement,
{
    let mut result = p.to_vec();
    syn_div_in_place(&mut result, a, b);
    result
}

/// Divides a polynomial by a polynomial of special form and saves the result into the original
/// polynomial.
///
/// Specifically, divides polynomial `p` by polynomial (x^`a` - `b`) using
/// [synthetic division](https://en.wikipedia.org/wiki/Synthetic_division) method and saves the
/// result into `p`. If the polynomials don't divide evenly, the remainder is ignored. Polynomial
/// `p` is expected to be in the coefficient form, and the result will be in coefficient form as
/// well.
///
/// This function is significantly faster than the generic `polynom::div()` function, and as
/// compared to `polynom::syn_div()` function, this function does not allocate any additional
/// memory.
///
/// # Panics
/// Panics if:
/// * `a` is zero;
/// * `b` is zero;
/// * `p.len()` is smaller than or equal to `a`.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p(x) = x^3 + x^2 + 2 * x + 2
/// let mut p = [
///     BaseElement::new(2),
///     BaseElement::new(2),
///     BaseElement::new(1),
///     BaseElement::new(1),
/// ];
///
/// // divide by x + 1
/// syn_div_in_place(&mut p, 1, -BaseElement::ONE);
///
/// // expected result = x^2 + 2
/// let expected = [
///     BaseElement::new(2),
///     BaseElement::ZERO,
///     BaseElement::new(1),
///     BaseElement::ZERO,
/// ];
///
/// assert_eq!(expected, p);
pub fn syn_div_in_place<E>(p: &mut [E], a: usize, b: E)
where
    E: FieldElement,
{
    assert!(a != 0, "divisor degree cannot be zero");
    assert!(b != E::ZERO, "constant cannot be zero");
    assert!(p.len() > a, "divisor degree cannot be greater than dividend size");

    if a == 1 {
        // if we are dividing by (x - `b`), we can use a single variable to keep track
        // of the remainder; this way, we can avoid shifting the values in the slice later
        let mut c = E::ZERO;
        for coeff in p.iter_mut().rev() {
            *coeff += b * c;
            mem::swap(coeff, &mut c);
        }
    } else {
        // if we are dividing by a polynomial of higher power, we need to keep track of the
        // full remainder. we do that in place, but then need to shift the values at the end
        // to discard the remainder
        let degree_offset = p.len() - a;
        if b == E::ONE {
            // if `b` is 1, no need to multiply by `b` in every iteration of the loop
            for i in (0..degree_offset).rev() {
                p[i] += p[i + a];
            }
        } else {
            for i in (0..degree_offset).rev() {
                p[i] += p[i + a] * b;
            }
        }
        // discard the remainder
        p.copy_within(a.., 0);
        p[degree_offset..].fill(E::ZERO);
    }
}

/// Divides a polynomial by a polynomial given its roots and saves the result into the original
/// polynomial.
///
/// Specifically, divides polynomial `p` by polynomial \prod_{i = 1}^m (x - `x_i`) using
/// [synthetic division](https://en.wikipedia.org/wiki/Synthetic_division) method and saves the
/// result into `p`. If the polynomials don't divide evenly, the remainder is ignored. Polynomial
/// `p` is expected to be in the coefficient form, and the result will be in coefficient form as
/// well.
///
/// This function is significantly faster than the generic `polynom::div()` function, using
/// the coefficients of the divisor.
///
/// # Panics
/// Panics if:
/// * `roots.len()` is zero;
/// * `p.len()` is smaller than or equal to `roots.len()`.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// // p(x) = x^3 - 7 * x + 6
/// let mut p = [
///     BaseElement::new(6),
///     -BaseElement::new(7),
///     BaseElement::new(0),
///     BaseElement::new(1),
/// ];
///
/// // divide by (x - 1) * (x - 2)
/// let zeros = vec![BaseElement::new(1), BaseElement::new(2)];
/// syn_div_roots_in_place(&mut p, &zeros);
///
/// // expected result = x + 3
/// let expected = [
///     BaseElement::new(3),
///     BaseElement::new(1),
///     BaseElement::ZERO,
///     BaseElement::ZERO,
/// ];
///
/// assert_eq!(expected, p);
pub fn syn_div_roots_in_place<E>(p: &mut [E], roots: &[E])
where
    E: FieldElement,
{
    assert!(!roots.is_empty(), "divisor should contain at least one linear factor");
    assert!(p.len() > roots.len(), "divisor degree cannot be greater than dividend size");

    for root in roots {
        let mut c = E::ZERO;
        for coeff in p.iter_mut().rev() {
            *coeff += *root * c;
            mem::swap(coeff, &mut c);
        }
    }
}

// DEGREE INFERENCE
// ================================================================================================

/// Returns the degree of the provided polynomial.
///
/// If the size of the provided slice is much larger than the degree of the polynomial (i.e.,
/// a large number of leading coefficients is ZERO), this operation can be quite inefficient.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// assert_eq!(0, degree_of::<BaseElement>(&[]));
/// assert_eq!(0, degree_of(&[BaseElement::ONE]));
/// assert_eq!(1, degree_of(&[BaseElement::ONE, BaseElement::new(2)]));
/// assert_eq!(1, degree_of(&[BaseElement::ONE, BaseElement::new(2), BaseElement::ZERO]));
/// assert_eq!(2, degree_of(&[BaseElement::ONE, BaseElement::new(2), BaseElement::new(3)]));
/// assert_eq!(
///     2,
///     degree_of(&[BaseElement::ONE, BaseElement::new(2), BaseElement::new(3), BaseElement::ZERO])
/// );
/// ```
pub fn degree_of<E>(poly: &[E]) -> usize
where
    E: FieldElement,
{
    for i in (0..poly.len()).rev() {
        if poly[i] != E::ZERO {
            return i;
        }
    }
    0
}

/// Returns a polynomial with all leading ZERO coefficients removed.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// let a = vec![1u128, 2, 3, 4, 5, 6, 0, 0]
///     .into_iter()
///     .map(BaseElement::new)
///     .collect::<Vec<_>>();
/// let b = remove_leading_zeros(&a);
/// assert_eq!(6, b.len());
/// assert_eq!(a[..6], b);
///
/// let a = vec![0u128, 0, 0, 0].into_iter().map(BaseElement::new).collect::<Vec<_>>();
/// let b = remove_leading_zeros(&a);
/// assert_eq!(0, b.len());
/// ```
pub fn remove_leading_zeros<E>(values: &[E]) -> Vec<E>
where
    E: FieldElement,
{
    for i in (0..values.len()).rev() {
        if values[i] != E::ZERO {
            return values[..(i + 1)].to_vec();
        }
    }
    vec![]
}

/// Returns the coefficients of polynomial given its roots.
///
/// # Examples
/// ```
/// # use winter_math::polynom::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// let xs = vec![1u128, 2].into_iter().map(BaseElement::new).collect::<Vec<_>>();
///
/// let mut expected_poly = vec![2u128, 3, 1].into_iter().map(BaseElement::new).collect::<Vec<_>>();
/// expected_poly[1] *= -BaseElement::ONE;
///
/// let poly = poly_from_roots(&xs);
/// assert_eq!(expected_poly, poly);
/// ```
pub fn poly_from_roots<E: FieldElement>(xs: &[E]) -> Vec<E> {
    let mut result = unsafe { utils::uninit_vector(xs.len() + 1) };
    fill_zero_roots(xs, &mut result);
    result
}

// HELPER FUNCTIONS
// ================================================================================================

fn fill_zero_roots<E: FieldElement>(xs: &[E], result: &mut [E]) {
    let mut n = result.len();
    n -= 1;
    result[n] = E::ONE;

    for i in 0..xs.len() {
        n -= 1;
        result[n] = E::ZERO;
        #[allow(clippy::assign_op_pattern)]
        for j in n..xs.len() {
            result[j] = result[j] - result[j + 1] * xs[i];
        }
    }
}
