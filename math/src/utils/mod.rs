// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{batch_iter_mut, iter_mut, uninit_vector};

use crate::{field::FieldElement, ExtensionOf};

// MATH FUNCTIONS
// ================================================================================================

/// Returns a vector containing successive powers of a given base.
///
/// More precisely, for base `b`, generates a vector with values [1, b, b^2, b^3, ..., b^(n-1)].
///
/// When `concurrent` feature is enabled, series generation is done concurrently in multiple
/// threads.
///
/// # Examples
/// ```
/// # use winter_math::get_power_series;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// let n = 2048;
/// let b = BaseElement::from(3u8);
///
/// let expected = (0..n).map(|p| b.exp((p as u64).into())).collect::<Vec<_>>();
///
/// let actual = get_power_series(b, n);
/// assert_eq!(expected, actual);
/// ```
pub fn get_power_series<E>(b: E, n: usize) -> Vec<E>
where
    E: FieldElement,
{
    let mut result = unsafe { uninit_vector(n) };
    batch_iter_mut!(&mut result, 1024, |batch: &mut [E], batch_offset: usize| {
        let start = b.exp((batch_offset as u64).into());
        fill_power_series(batch, b, start);
    });
    result
}

/// Returns a vector containing successive powers of a given base offset by the specified value.
///
/// More precisely, for base `b` and offset `s`, generates a vector with values
/// [s, s * b, s * b^2, s * b^3, ..., s * b^(n-1)].
///
/// When `concurrent` feature is enabled, series generation is done concurrently in multiple
/// threads.
///
/// # Examples
/// ```
/// # use winter_math::get_power_series_with_offset;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// let n = 2048;
/// let b = BaseElement::from(3u8);
/// let s = BaseElement::from(7u8);
///
/// let expected = (0..n).map(|p| s * b.exp((p as u64).into())).collect::<Vec<_>>();
///
/// let actual = get_power_series_with_offset(b, s, n);
/// assert_eq!(expected, actual);
/// ```
pub fn get_power_series_with_offset<E>(b: E, s: E, n: usize) -> Vec<E>
where
    E: FieldElement,
{
    let mut result = unsafe { uninit_vector(n) };
    batch_iter_mut!(&mut result, 1024, |batch: &mut [E], batch_offset: usize| {
        let start = s * b.exp((batch_offset as u64).into());
        fill_power_series(batch, b, start);
    });
    result
}

/// Computes element-wise sum of the provided vectors, and stores the result in the first vector.
///
/// When `concurrent` feature is enabled, the summation is performed concurrently in multiple
/// threads.
///
/// # Panics
/// Panics if lengths of `a` and `b` vectors are not the same.
///
/// # Examples
/// ```
/// # use winter_math::add_in_place;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// # use rand_utils::rand_vector;
/// let a: Vec<BaseElement> = rand_vector(2048);
/// let b: Vec<BaseElement> = rand_vector(2048);
///
/// let mut c = a.clone();
/// add_in_place(&mut c, &b);
///
/// for ((a, b), c) in a.into_iter().zip(b).zip(c) {
///     assert_eq!(a + b, c);
/// }
/// ```
pub fn add_in_place<E>(a: &mut [E], b: &[E])
where
    E: FieldElement,
{
    assert!(a.len() == b.len(), "number of values must be the same for both operands");
    iter_mut!(a).zip(b).for_each(|(a, &b)| *a += b);
}

/// Multiplies a sequence of values by a scalar and accumulates the results.
///
/// More precisely, computes `a[i]` + `b[i]` * `c` for all `i` and saves result into `a[i]`.
///
/// When `concurrent` feature is enabled, the computation is performed concurrently in multiple
/// threads.
///
/// # Panics
/// Panics if lengths of `a` and `b` slices are not the same.
///
/// # Examples
/// ```
/// # use winter_math::mul_acc;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// # use rand_utils::rand_vector;
/// let a: Vec<BaseElement> = rand_vector(2048);
/// let b: Vec<BaseElement> = rand_vector(2048);
/// let c = BaseElement::new(12345);
///
/// let mut d = a.clone();
/// mul_acc(&mut d, &b, c);
///
/// for ((a, b), d) in a.into_iter().zip(b).zip(d) {
///     assert_eq!(a + b * c, d);
/// }
/// ```
pub fn mul_acc<F, E>(a: &mut [E], b: &[F], c: E)
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    assert!(a.len() == b.len(), "number of values must be the same for both slices");
    iter_mut!(a).zip(b).for_each(|(a, &b)| *a += c.mul_base(b));
}

/// Computes a multiplicative inverse of a sequence of elements using batch inversion method.
///
/// Any ZEROs in the provided sequence are ignored.
///
/// When `concurrent` feature is enabled, the inversion is performed concurrently in multiple
/// threads.
///
/// This function is significantly faster than inverting elements one-by-one because it
/// essentially transforms `n` inversions into `3 * n` multiplications + 1 inversion.
///
/// # Examples
/// ```
/// # use winter_math::batch_inversion;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement};
/// # use rand_utils::rand_vector;
/// let a: Vec<BaseElement> = rand_vector(2048);
/// let b = batch_inversion(&a);
///
/// for (&a, &b) in a.iter().zip(b.iter()) {
///     assert_eq!(a.inv(), b);
/// }
/// ```
pub fn batch_inversion<E>(values: &[E]) -> Vec<E>
where
    E: FieldElement,
{
    let mut result: Vec<E> = unsafe { uninit_vector(values.len()) };
    batch_iter_mut!(&mut result, 1024, |batch: &mut [E], batch_offset: usize| {
        let start = batch_offset;
        let end = start + batch.len();
        serial_batch_inversion(&values[start..end], batch);
    });
    result
}

// HELPER FUNCTIONS
// ------------------------------------------------------------------------------------------------

#[inline(always)]
fn fill_power_series<E: FieldElement>(result: &mut [E], base: E, start: E) {
    result[0] = start;
    for i in 1..result.len() {
        result[i] = result[i - 1] * base;
    }
}

fn serial_batch_inversion<E: FieldElement>(values: &[E], result: &mut [E]) {
    let mut last = E::ONE;
    for (result, &value) in result.iter_mut().zip(values.iter()) {
        *result = last;
        if value != E::ZERO {
            last *= value;
        }
    }

    last = last.inv();

    for i in (0..values.len()).rev() {
        if values[i] == E::ZERO {
            result[i] = E::ZERO;
        } else {
            result[i] *= last;
            last *= values[i];
        }
    }
}
