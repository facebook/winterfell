// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! FFT-based polynomial evaluation and interpolation.
//!
//! Functions in this module can be used to evaluate and interpolate polynomials over domains
//! which are multiplicative subgroups of finite fields and have lengths equal to powers of two.
//! As compared to evaluation and interpolation functions available in the `polynom` module,
//! these functions are much more efficient: their runtime complexity is O(`n` log `n`), where
//! `n` is the domain size.

use alloc::vec::Vec;

use crate::{
    fft::fft_inputs::FftInputs,
    field::{FieldElement, StarkField},
    utils::get_power_series,
};

pub mod fft_inputs;
pub mod real_u64;
mod serial;

#[cfg(feature = "concurrent")]
mod concurrent;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================
const MIN_CONCURRENT_SIZE: usize = 1024;

// POLYNOMIAL EVALUATION
// ================================================================================================

/// Evaluates a polynomial on all points of the specified domain using the FFT algorithm.
///
/// Uses the [FFT](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)) algorithm
/// to evaluate polynomial `p` on all points of a domain defined by the length of `p` in the field
/// specified by the `B` type parameter. The evaluation is done in-place, meaning no additional
/// memory is allocated and `p` is updated with results of the evaluation. The polynomial `p`
/// is expected to be in coefficient form.
///
/// The complexity of evaluation is O(`n` log(`n`)), where `n` is the size of the domain.
///
/// The size of the domain is assumed to be equal to `p.len()` which must be a power of two. The
/// base field specified by `B` must have a multiplicative subgroup of size equal to `p.len()`.
///
/// The `twiddles` needed for evaluation can be obtained via `fft::get_twiddles()` function using
/// `p.len()` as the domain size parameter. This implies that `twiddles.len()` must be equal to
/// `p.len()` / 2.
///
/// When `concurrent` feature is enabled, the evaluation is done in multiple threads.
///
/// # Panics
/// Panics if:
/// * Length of `p` is not a power of two.
/// * Length of `twiddles` is not `p.len()` / 2.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `p.len()`.
///
/// # Examples
/// ```
/// # use winter_math::{polynom, fft::*, get_power_series};
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// # use rand_utils::rand_vector;
/// let n = 2048;
///
/// // build a random polynomial
/// let mut p: Vec<BaseElement> = rand_vector(n);
///
/// // evaluate the polynomial over the domain using regular polynomial evaluation
/// let g = BaseElement::get_root_of_unity(n.ilog2());
/// let domain = get_power_series(g, n);
/// let expected = polynom::eval_many(&p, &domain);
///
/// // evaluate the polynomial over the domain using FFT-based evaluation
/// let twiddles = get_twiddles::<BaseElement>(p.len());
/// evaluate_poly(&mut p, &twiddles);
///
/// assert_eq!(expected, p);
/// ```
pub fn evaluate_poly<B, E>(p: &mut [E], twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(p.len().is_power_of_two(), "number of coefficients must be a power of 2");
    assert_eq!(
        p.len(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        p.len() / 2,
        twiddles.len()
    );
    assert!(
        p.len().ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        p.len()
    );

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && p.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::evaluate_poly(p, twiddles);
    } else {
        serial::evaluate_poly(p, twiddles);
    }
}

/// Evaluates a polynomial on all points of the specified (shifted) domain using the FFT algorithm.
///
/// Uses the [FFT](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general)) algorithm
/// to evaluate polynomial `p` on all points of a domain defined by the length of `p`, expanded
/// by the `blowup_factor`, and shifted by the `domain_offset` in the field specified by the `B`
/// type parameter. The polynomial `p` is expected to be in coefficient form.
///
/// The complexity of evaluation is O(`n` log(`n`)), where `n` is the size of the domain.
///
/// The size of the domain is assumed to be equal to `p.len()` * `blowup_factor` both of which must
/// be powers of two. The base field specified by `B` must have a multiplicative subgroup of size
/// equal to `p.len()` * `blowup_factor`.
///
/// The shifted domain is defined as the original domain with every element multiplied by the
/// `domain_offset`.
///
/// The `twiddles` needed for evaluation can be obtained via `fft::get_twiddles()` function using
/// `p.len()` as the domain size parameter. This implies that `twiddles.len()` must be equal to
/// `p.len()` / 2.
///
/// When `concurrent` feature is enabled, the evaluation is done in multiple threads.
///
/// # Panics
/// Panics if:
/// * Length of `p` is not a power of two.
/// * `blowup_factor` is not a power of two.
/// * Length of `twiddles` is not `p.len()` / 2.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `p.len()`.
/// * `domain_offset` is ZERO.
///
/// # Examples
/// ```
/// # use winter_math::{polynom, fft::*, get_power_series};
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// # use rand_utils::rand_vector;
/// let n = 2048;
/// let offset = BaseElement::GENERATOR;
/// let blowup_factor = 2;
///
/// // build a random polynomial
/// let mut p: Vec<BaseElement> = rand_vector(n / blowup_factor);
///
/// // evaluate the polynomial over the domain using regular polynomial evaluation
/// let g = BaseElement::get_root_of_unity(n.ilog2());
/// let domain = get_power_series(g, n);
/// let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
/// let expected = polynom::eval_many(&p, &shifted_domain);
///
/// // evaluate the polynomial over the domain using FFT-based evaluation
/// let twiddles = get_twiddles::<BaseElement>(p.len());
/// let actual = evaluate_poly_with_offset(&mut p, &twiddles, offset, blowup_factor);
///
/// assert_eq!(expected, actual);
/// ```
pub fn evaluate_poly_with_offset<B, E>(
    p: &[E],
    twiddles: &[B],
    domain_offset: B,
    blowup_factor: usize,
) -> Vec<E>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(p.len().is_power_of_two(), "number of coefficients must be a power of 2");
    assert!(blowup_factor.is_power_of_two(), "blowup factor must be a power of 2");
    assert_eq!(
        p.len(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        p.len() / 2,
        twiddles.len()
    );
    assert!(
        (p.len() * blowup_factor).ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        p.len() * blowup_factor
    );
    assert_ne!(domain_offset, B::ZERO, "domain offset cannot be zero");

    // assign a dummy value here to make the compiler happy
    #[allow(unused_assignments)]
    let mut result = Vec::new();

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && p.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        {
            result =
                concurrent::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);
        }
    } else {
        result = serial::evaluate_poly_with_offset(p, twiddles, domain_offset, blowup_factor);
    }

    result
}

// POLYNOMIAL INTERPOLATION
// ================================================================================================

/// Interpolates evaluations of a polynomial over the specified domain into a polynomial in
/// coefficient from using the FFT algorithm.
///
/// Uses the inverse [FFT](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general))
/// algorithm to interpolate a polynomial from its evaluations over a domain defined by the
/// length of `evaluations` in the field specified by the `B` type parameter.  The interpolation
/// is done in-place, meaning no additional memory is allocated and the evaluations contained in
/// `evaluations` are replaced with polynomial coefficients.
///
/// The complexity of interpolation is O(`n` log(`n`)), where `n` is the size of the domain.
///
/// The size of the domain is assumed to be equal to `evaluations.len()` which must be a power
/// of two. The base field specified by `B` must have a multiplicative subgroup of size equal
/// to `evaluations.len()`.
///
/// The `inv_twiddles` needed for interpolation can be obtained via `fft::get_inv_twiddles()`
/// function using `evaluations.len()` as the domain size parameter. This implies that
/// `twiddles.len()` must be equal to `evaluations.len()` / 2.
///
/// When `concurrent` feature is enabled, the interpolation is done in multiple threads.
///
/// # Panics
/// Panics if:
/// * Length of `evaluations` is not a power of two.
/// * Length of `inv_twiddles` is not `evaluations.len()` / 2.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `evaluations.len()`.
///
/// # Examples
/// ```
/// # use winter_math::{polynom, fft::*, get_power_series};
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// # use rand_utils::rand_vector;
/// let n = 2048;
///
/// // build a random polynomial
/// let p: Vec<BaseElement> = rand_vector(n);
///
/// // evaluate the polynomial over the domain using regular polynomial evaluation
/// let g = BaseElement::get_root_of_unity(n.ilog2());
/// let domain = get_power_series(g, n);
/// let mut ys = polynom::eval_many(&p, &domain);
///
/// // interpolate the evaluations into a polynomial
/// let inv_twiddles = get_inv_twiddles::<BaseElement>(ys.len());
/// interpolate_poly(&mut ys, &inv_twiddles);
///
/// assert_eq!(p, ys);
/// ```
pub fn interpolate_poly<B, E>(evaluations: &mut [E], inv_twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(
        evaluations.len().is_power_of_two(),
        "number of evaluations must be a power of 2, but was {}",
        evaluations.len()
    );
    assert_eq!(
        evaluations.len(),
        inv_twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        evaluations.len() / 2,
        inv_twiddles.len()
    );
    assert!(
        evaluations.len().ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        evaluations.len()
    );

    // when `concurrent` feature is enabled, run the concurrent version of interpolate_poly;
    // unless the number of evaluations is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && evaluations.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::interpolate_poly(evaluations, inv_twiddles);
    } else {
        serial::interpolate_poly(evaluations, inv_twiddles);
    }
}

/// Interpolates evaluations of a polynomial over the specified (shifted) domain into a polynomial
/// in coefficient from using the FFT algorithm.
///
/// Uses the inverse [FFT](https://en.wikipedia.org/wiki/Discrete_Fourier_transform_(general))
/// algorithm to interpolate a polynomial from its evaluations over a domain defined by the
/// length of `evaluations` and shifted by the `domain_offset` in the field specified by the `B`
/// type parameter. The interpolation is done in-place, meaning no additional memory is allocated
/// and the evaluations contained in `evaluations` are replaced with polynomial coefficients.
///
/// The complexity of interpolation is O(`n` log(`n`)), where `n` is the size of the domain.
///
/// The size of the domain is assumed to be equal to `evaluations.len()` which must be a power
/// of two. The base field specified by `B` must have a multiplicative subgroup of size equal
/// to `evaluations.len()`.
///
/// The shifted domain is defined as the original domain with every element multiplied by the
/// `domain_offset`.
///
/// The `inv_twiddles` needed for interpolation can be obtained via `fft::get_inv_twiddles()`
/// function using `evaluations.len()` as the domain size parameter. This implies that
/// `twiddles.len()` must be equal to `evaluations.len()` / 2.
///
/// When `concurrent` feature is enabled, the interpolation is done in multiple threads.
///
/// # Panics
/// Panics if:
/// * Length of `evaluations` is not a power of two.
/// * Length of `inv_twiddles` is not `evaluations.len()` / 2.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `evaluations.len()`.
/// * `domain_offset` is ZERO.
///
/// # Examples
/// ```
/// # use winter_math::{polynom, fft::*, get_power_series};
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// # use rand_utils::rand_vector;
/// let n = 2048;
/// let offset = BaseElement::GENERATOR;
///
/// // build a random polynomial
/// let p: Vec<BaseElement> = rand_vector(n);
///
/// // evaluate the polynomial over the domain using regular polynomial evaluation
/// let g = BaseElement::get_root_of_unity(n.ilog2());
/// let domain = get_power_series(g, n);
/// let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
/// let mut ys = polynom::eval_many(&p, &shifted_domain);
///
/// // interpolate the evaluations into a polynomial
/// let inv_twiddles = get_inv_twiddles::<BaseElement>(ys.len());
/// interpolate_poly_with_offset(&mut ys, &inv_twiddles, offset);
///
/// assert_eq!(p, ys);
/// ```
pub fn interpolate_poly_with_offset<B, E>(
    evaluations: &mut [E],
    inv_twiddles: &[B],
    domain_offset: B,
) where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(
        evaluations.len().is_power_of_two(),
        "number of evaluations must be a power of 2, but was {}",
        evaluations.len()
    );
    assert_eq!(
        evaluations.len(),
        inv_twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        evaluations.len() / 2,
        inv_twiddles.len()
    );
    assert!(
        evaluations.len().ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        evaluations.len()
    );
    assert_ne!(domain_offset, B::ZERO, "domain offset cannot be zero");

    // when `concurrent` feature is enabled, run the concurrent version of the function; unless
    // the polynomial is small, then don't bother with the concurrent version
    if cfg!(feature = "concurrent") && evaluations.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::interpolate_poly_with_offset(evaluations, inv_twiddles, domain_offset);
    } else {
        serial::interpolate_poly_with_offset(evaluations, inv_twiddles, domain_offset);
    }
}

// RAW FFT ALGORITHM
// ================================================================================================

/// Executes a single-threaded version of the FFT algorithm on the provided values.
///
/// The evaluation is done in-place, meaning the function does not allocate any additional memory,
/// and the results are written back into `values`.
///
/// The `twiddles` needed for evaluation can be obtained via `fft::get_twiddles()` function using
/// `values.len()` as the domain size parameter. This implies that `twiddles.len()` must be equal
/// to `values.len()` / 2.
///
/// # Panics
/// Panics if:
/// * Length of `values` is not a power of two.
/// * Length of `twiddles` is not `values.len()` / 2.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `values.len()`.
pub fn serial_fft<B, E>(values: &mut [E], twiddles: &[B])
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(
        values.len().is_power_of_two(),
        "number of values must be a power of 2, but was {}",
        values.len()
    );
    assert_eq!(
        values.len(),
        twiddles.len() * 2,
        "invalid number of twiddles: expected {} but received {}",
        values.len() / 2,
        twiddles.len()
    );
    assert!(
        values.len().ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        values.len()
    );
    values.fft_in_place(twiddles);
    values.permute();
}

// TWIDDLES
// ================================================================================================

/// Returns a set of twiddles for the specified domain size.
///
/// These twiddles can then be used for FFT-based polynomial evaluation. The length of the returned
/// vector will be equal to `domain_size` / 2.
///
/// When `concurrent` feature is enabled, the twiddles are generated in multiple threads.
///
/// # Panics
/// Panics if:
/// * `domain_size` is not a power of two.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `domain_size`.
///
/// # Examples
/// ```
/// # use winter_math::fft::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// let n = 2048;
/// let twiddles = get_twiddles::<BaseElement>(n);
///
/// assert_eq!(n / 2, twiddles.len());
/// ```
pub fn get_twiddles<B>(domain_size: usize) -> Vec<B>
where
    B: StarkField,
{
    assert!(domain_size.is_power_of_two(), "domain size must be a power of 2");
    assert!(
        domain_size.ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {domain_size} does not exist in the specified base field"
    );
    let root = B::get_root_of_unity(domain_size.ilog2());
    let mut twiddles = get_power_series(root, domain_size / 2);
    permute(&mut twiddles);
    twiddles
}

/// Returns a set of inverse twiddles for the specified domain size.
///
/// These twiddles can then be used for FFT-based polynomial interpolation. The length of the
/// returned vector will be equal to `domain_size` / 2.
///
/// When `concurrent` feature is enabled, the twiddles are generated in multiple threads.
///
/// # Panics
/// Panics if:
/// * `domain_size` is not a power of two.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `domain_size`.
///
/// # Examples
/// ```
/// # use winter_math::fft::*;
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// let n = 2048;
/// let inv_twiddles = get_inv_twiddles::<BaseElement>(n);
///
/// assert_eq!(n / 2, inv_twiddles.len());
/// ```
pub fn get_inv_twiddles<B>(domain_size: usize) -> Vec<B>
where
    B: StarkField,
{
    assert!(domain_size.is_power_of_two(), "domain size must be a power of 2");
    assert!(
        domain_size.ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {domain_size} does not exist in the specified base field"
    );
    let root = B::get_root_of_unity(domain_size.ilog2());
    let inv_root = root.exp((domain_size as u32 - 1).into());
    let mut inv_twiddles = get_power_series(inv_root, domain_size / 2);
    permute(&mut inv_twiddles);
    inv_twiddles
}

// DEGREE INFERENCE
// ================================================================================================

/// Returns the degree of a polynomial implied by the provided evaluations.
///
/// The polynomial is assumed to be evaluated over a multiplicative subgroup of length equal to
/// the length of `evaluations` in the field defined by `B` type parameter and shifted by the
/// `domain_offset`.
///
/// The shifted domain is defined as the original domain with every element multiplied by the
/// `domain_offset`.
///
/// The degree is determined by first interpolating the polynomial into a coefficient form using
/// FFT-based polynomial interpolation, and then finding the first non-zero coefficient.
///
/// # Panics
/// Panics if
/// * Length of `evaluations` is not a power of two.
/// * Field specified by `B` does not contain a multiplicative subgroup of size `domain_size`.
/// * `domain_offset` is ZERO.
///
/// # Examples
/// ```
/// # use winter_math::{polynom, fft::*, get_power_series};
/// # use winter_math::{fields::{f128::BaseElement}, FieldElement, StarkField};
/// let offset = BaseElement::GENERATOR;
/// // p(x) = x^2 + 1
/// let p = [BaseElement::new(1), BaseElement::ZERO, BaseElement::new(1), BaseElement::ZERO];
///
/// let g = BaseElement::get_root_of_unity(p.len().ilog2());
/// let domain = get_power_series(g, p.len());
/// let shifted_domain = domain.iter().map(|&x| x * offset).collect::<Vec<_>>();
/// let evaluations = polynom::eval_many(&p, &shifted_domain);
///
/// assert_eq!(2, infer_degree(&evaluations, offset));
/// ```
pub fn infer_degree<B, E>(evaluations: &[E], domain_offset: B) -> usize
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    assert!(
        evaluations.len().is_power_of_two(),
        "number of evaluations must be a power of 2"
    );
    assert!(
        evaluations.len().ilog2() <= B::TWO_ADICITY,
        "multiplicative subgroup of size {} does not exist in the specified base field",
        evaluations.len()
    );
    assert_ne!(domain_offset, B::ZERO, "domain offset cannot be zero");
    let mut poly = evaluations.to_vec();
    let inv_twiddles = get_inv_twiddles::<B>(evaluations.len());
    interpolate_poly_with_offset(&mut poly, &inv_twiddles, domain_offset);
    super::polynom::degree_of(&poly)
}

// PERMUTATIONS
// ================================================================================================

/// Computes bit reverse of the specified index in the domain of the specified size.
///
/// Domain size is assumed to be a power of two and index must be smaller than domain size.
pub fn permute_index(size: usize, index: usize) -> usize {
    const USIZE_BITS: u32 = 0_usize.count_zeros();

    debug_assert!(index < size);
    debug_assert!(size.is_power_of_two());

    let bits = size.trailing_zeros();
    index.reverse_bits().wrapping_shr(USIZE_BITS - bits)
}

fn permute<E: FieldElement>(v: &mut [E]) {
    if cfg!(feature = "concurrent") && v.len() >= MIN_CONCURRENT_SIZE {
        #[cfg(feature = "concurrent")]
        concurrent::permute(v);
    } else {
        FftInputs::permute(v);
    }
}
