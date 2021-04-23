// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{field::FieldElement, utils as crate_utils};
use std::mem;

#[cfg(test)]
mod tests;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates polynomial `p` at coordinate `x`.
pub fn eval<B, E>(p: &[B], x: E) -> E
where
    B: FieldElement,
    E: FieldElement + From<B>,
{
    // Horner evaluation
    p.iter()
        .rev()
        .fold(E::ZERO, |acc, &coeff| acc * x + E::from(coeff))
}

/// Evaluates polynomial `p` at all coordinates in `xs` slice.
pub fn eval_many<B, E>(p: &[B], xs: &[E]) -> Vec<E>
where
    B: FieldElement,
    E: FieldElement + From<B>,
{
    xs.iter().map(|x| eval(p, *x)).collect()
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Uses Lagrange interpolation to build a polynomial from X and Y coordinates.
pub fn interpolate<E: FieldElement>(xs: &[E], ys: &[E], remove_leading_zeros: bool) -> Vec<E> {
    debug_assert!(
        xs.len() == ys.len(),
        "Number of X and Y coordinates must be the same"
    );

    let roots = get_zero_roots(xs);
    let mut divisor = [E::ZERO, E::ONE];
    let mut numerators: Vec<Vec<E>> = Vec::with_capacity(xs.len());
    for xcoord in xs {
        divisor[0] = -*xcoord;
        numerators.push(div(&roots, &divisor));
    }

    let mut denominators: Vec<E> = Vec::with_capacity(xs.len());
    for i in 0..xs.len() {
        denominators.push(eval(&numerators[i], xs[i]));
    }
    let denominators = crate_utils::batch_inversion(&denominators);

    let mut result = E::zeroed_vector(xs.len());
    for i in 0..xs.len() {
        let y_slice = ys[i] * denominators[i];
        if ys[i] != E::ZERO {
            for (j, res) in result.iter_mut().enumerate() {
                if numerators[i][j] != E::ZERO {
                    *res += numerators[i][j] * y_slice;
                }
            }
        }
    }

    if remove_leading_zeros {
        crate_utils::remove_leading_zeros(&result)
    } else {
        result
    }
}

// POLYNOMIAL MATH OPERATIONS
// ================================================================================================

/// Adds polynomial `a` to polynomial `b`
pub fn add<E: FieldElement>(a: &[E], b: &[E]) -> Vec<E> {
    let result_len = std::cmp::max(a.len(), b.len());
    let mut result = Vec::with_capacity(result_len);
    for i in 0..result_len {
        let c1 = if i < a.len() { a[i] } else { E::ZERO };
        let c2 = if i < b.len() { b[i] } else { E::ZERO };
        result.push(c1 + c2);
    }
    result
}

/// Subtracts polynomial `b` from polynomial `a`
pub fn sub<E: FieldElement>(a: &[E], b: &[E]) -> Vec<E> {
    let result_len = std::cmp::max(a.len(), b.len());
    let mut result = Vec::with_capacity(result_len);
    for i in 0..result_len {
        let c1 = if i < a.len() { a[i] } else { E::ZERO };
        let c2 = if i < b.len() { b[i] } else { E::ZERO };
        result.push(c1 - c2);
    }
    result
}

/// Multiplies polynomial `a` by polynomial `b`
pub fn mul<E: FieldElement>(a: &[E], b: &[E]) -> Vec<E> {
    let result_len = a.len() + b.len() - 1;
    let mut result = E::zeroed_vector(result_len);
    for i in 0..a.len() {
        for j in 0..b.len() {
            let s = a[i] * b[j];
            result[i + j] += s;
        }
    }
    result
}

/// Multiplies every coefficient of polynomial `p` by constant `k`
pub fn mul_by_const<E: FieldElement>(p: &[E], k: E) -> Vec<E> {
    let mut result = Vec::with_capacity(p.len());
    for coeff in p {
        result.push(*coeff * k);
    }
    result
}

/// Divides polynomial `a` by polynomial `b`; if the polynomials don't divide evenly,
/// the remainder is ignored.
pub fn div<E: FieldElement>(a: &[E], b: &[E]) -> Vec<E> {
    let mut apos = degree_of(a);
    let mut a = a.to_vec();

    let bpos = degree_of(b);
    assert!(apos >= bpos, "cannot divide by polynomial of higher degree");
    if bpos == 0 {
        assert!(b[0] != E::ZERO, "cannot divide polynomial by zero");
    }

    let mut result = E::zeroed_vector(apos - bpos + 1);
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

/// Divides polynomial `p` by polynomial (x^`a` - `b`) using synthetic division method;
/// if the polynomials don't divide evenly, the remainder is ignored.
///
/// Panics if:
/// * `a` is zero;
/// * `b` is zero;
pub fn syn_div<E: FieldElement>(p: &[E], a: usize, b: E) -> Vec<E> {
    let mut result = p.to_vec();
    syn_div_in_place(&mut result, a, b);
    result
}

/// Divides polynomial `p` by polynomial (x^`a` - `b`) using synthetic division method
/// and stores the result in `p`; if the polynomials don't divide evenly, the remainder
/// is ignored.
///
/// Panics if:
/// * `a` is zero;
/// * `b` is zero;
pub fn syn_div_in_place<E: FieldElement>(p: &mut [E], a: usize, b: E) {
    assert!(a != 0, "divisor degree cannot be zero");
    assert!(b != E::ZERO, "constant cannot be zero");

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

/// Divides polynomial `p` by polynomial (x^`a` - 1) / (x - `exception`) using synthetic
/// division method and stores the result in `p`; if the polynomials don't divide evenly,
/// the remainder is ignored.
///
/// Panics if:
/// * `a` is zero;
/// * `exception` is zero;
pub fn syn_div_in_place_with_exception<E: FieldElement>(p: &mut [E], a: usize, exception: E) {
    assert!(a != 0, "divisor degree cannot be zero");
    assert!(exception != E::ZERO, "exception cannot be zero");

    // compute p / (x^a - 1)
    let degree_offset = p.len() - a;
    for i in (0..degree_offset).rev() {
        p[i] += p[i + a];
    }

    // multiply by (x - exception); this skips the last iteration of the loop so that we
    // can avoid resizing `p`; the last iteration will be applied at the end of the function
    // once remainder terms have been discarded
    let exception = -exception;
    let mut next_term = p[0];
    p[0] = E::ZERO;
    for i in 0..(p.len() - 1) {
        p[i] += next_term * exception;
        mem::swap(&mut next_term, &mut p[i + 1]);
    }

    // discard the remainder terms
    p.copy_within(a.., 0);
    p[degree_offset..].fill(E::ZERO);

    // apply the last iteration of the multiplication loop
    p[degree_offset - 1] += next_term * exception;
    p[degree_offset] = next_term;
}

// DEGREE INFERENCE
// ================================================================================================

/// Returns degree of the polynomial `poly`
pub fn degree_of<E: FieldElement>(poly: &[E]) -> usize {
    for i in (0..poly.len()).rev() {
        if poly[i] != E::ZERO {
            return i;
        }
    }
    0
}

// HELPER FUNCTIONS
// ================================================================================================
fn get_zero_roots<E: FieldElement>(xs: &[E]) -> Vec<E> {
    let mut n = xs.len() + 1;
    let mut result = utils::uninit_vector(n);

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

    result
}
