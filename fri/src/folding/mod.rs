// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains functions for folding FRI layers.
//!
//! This module is exposed publicly primarily for benchmarking and documentation purposes. The
//! functions contained here are not intended to be used by the end-user of the crate.

use alloc::vec::Vec;

use math::{
    fft::{get_inv_twiddles, serial_fft},
    get_power_series_with_offset, polynom, FieldElement, StarkField,
};
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{iter_mut, uninit_vector};

// DEGREE-RESPECTING PROJECTION
// ================================================================================================
/// Applies degree-respecting projection to evaluations of a polynomial.
///
/// This process reduces the  degree of the polynomial implied by the `evaluations` by `N`.
/// For example, for `N` = 4, this is equivalent to the following:
/// - Let `evaluations` contain the evaluations of polynomial *f*(x) of degree *k*.
/// - Group coefficients of *f* so that *f*(x) = a(x) + x * b(x) + x^2 * c(x) + x^3 * d(x)
/// - Compute random linear combination of polynomials a, b, c, d as
///   *f'*(x) = a + α * b + α^2 * c + α^3 * d, where α is an element drawn uniformly at random from
///   the entire field.
/// - evaluate f'(x) on a domain which consists of x^4 from the original domain (and thus is
///   1/4 the size).
///
/// However, the reduction is performed without converting the polynomials into coefficient form.
/// That is, we can go directly form evaluations to folded evaluations. For this, for each
/// evaluation in the folded domain, we need `N` evaluations in the source domain. For example,
/// for the case of `N` = 4, to compute the evaluation of *f'*(x) we need to have evaluations of
/// *f*(x) from the source domain at x^{1/4}, x^{2/4}, x^{3/4}, x.
///
/// This function expect the `evaluations` to be already in a transposed form such that all
/// evaluations needed to compute a single evaluation in the folded domain are next to each other.
///
/// The example below shows the equivalence of performing the projection via coefficient form and
/// via evaluation form for `N` = 2.
/// ```
/// # use math::{StarkField, FieldElement, fields::f128::BaseElement, get_power_series_with_offset, polynom};
/// # use rand_utils::{rand_value, rand_vector};
/// # use utils::transpose_slice;
/// # use winter_fri::folding::apply_drp;
/// // generate random alpha
/// let alpha: BaseElement = rand_value();
///
/// // degree 7 polynomial f(x)
/// let poly: Vec<BaseElement> = rand_vector(8);
///
/// // f'(x) = g(x) + alpha * h(x) such that g(x) consists of even coefficients of f(x) and h(x)
/// // consists of odd coefficients of f(x). This is equivalent to using `folding_factor = 2`.
/// let mut folded_poly = Vec::new();
/// for i in 0..poly.len() / 2 {
///     folded_poly.push(poly[2 * i] + alpha * poly[2 * i + 1]);
/// }
///
/// // build a domain of 32 elements
/// let n = 32_usize;
/// let offset = BaseElement::GENERATOR;
/// let g = BaseElement::get_root_of_unity(n.trailing_zeros());
/// let domain = get_power_series_with_offset(g, offset, n);
///
/// // build a folded domain of half the size, such that x in the source domain maps to
/// // x^2 in the folded domain.
/// let g = BaseElement::get_root_of_unity((n / 2).trailing_zeros());
/// let folded_domain = get_power_series_with_offset(g, offset.exp(2), n / 2);
///
/// // evaluate the polynomials over their respective domains
/// let evaluations = polynom::eval_many(&poly, &domain);
/// let folded_evaluations = polynom::eval_many(&folded_poly, &folded_domain);
///
/// // use DRP to perform folding without converting polynomials into coefficient form
/// let transposed_evaluations = transpose_slice::<BaseElement, 2>(&evaluations);
/// let drp_evaluations = apply_drp(&transposed_evaluations, offset, alpha);
///
/// // applying DRP should be equivalent to folding polynomials in coefficient form
/// assert_eq!(folded_evaluations, drp_evaluations);
/// ```
pub fn apply_drp<B, E, const N: usize>(values: &[[E; N]], domain_offset: B, alpha: E) -> Vec<E>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    // build offset inverses and twiddles used during polynomial interpolation
    let inv_offsets = get_inv_offsets(values.len(), domain_offset, N);
    let inv_twiddles = get_inv_twiddles::<B>(N);
    let len_offset = E::inv((N as u32).into());

    let mut result = unsafe { uninit_vector(values.len()) };
    iter_mut!(result)
        .zip(values)
        .zip(inv_offsets)
        .for_each(|((result, values), domain_offset)| {
            // interpolate the values into a polynomial; this is similar to interpolation with
            // offset implemented in math::fft module
            let mut poly = *values;
            serial_fft(&mut poly, &inv_twiddles);

            let mut offset = len_offset;
            let domain_offset = E::from(domain_offset);
            for coeff in poly.iter_mut() {
                *coeff *= offset;
                offset *= domain_offset;
            }

            // evaluate the polynomial at alpha, and save the result
            *result = polynom::eval(&poly, alpha)
        });

    result
}

// POSITION FOLDING
// ================================================================================================
/// Maps positions in the source domain, to positions in the folded domain.
///
/// The size of the folded domain is reduced by the `folding_factor` as compared to the size of the
/// source domain. Thus, the original positions may fall outside of the folded domain. To map
/// positions in the source domain to positions in the folded domain, we simply compute
/// `new_position = old_position % folded_domain_size` and discard duplicates.
///
/// ```
/// # use winter_fri::folding::fold_positions;
/// let positions = [1, 9, 12, 20];
/// let folded_positions = fold_positions(&positions, 32, 4);
///
/// // 1 and 9 should map to 1; 12 and 20 should map to 4
/// assert_eq!(vec![1, 4], folded_positions);
/// ```
///
/// The domains we usually work with have the following form: c, c * ω, c * ω^2, ..., c * ω^(*n*-1),
/// where *n* is the size of the domain, ω is *n*th root of unity, and c is the domain offset. Thus,
/// the procedure described above maps c * ω^*i* to (c * ω^*i*)^*k*, where *k* is the folding factor.
/// ```
/// # use math::{fields::f128::BaseElement, StarkField, FieldElement, get_power_series_with_offset};
/// // build a domain of size 32
/// let n = 32usize;
/// let c = BaseElement::GENERATOR;
/// let g = BaseElement::get_root_of_unity(n.trailing_zeros());
/// let source_domain = get_power_series_with_offset(g, c, n);
///
/// // build a domain of size 8 (folding_factor = 4)
/// let g = BaseElement::get_root_of_unity((n / 4).trailing_zeros());
/// let folded_domain = get_power_series_with_offset(g, c.exp(4_u32.into()), (n / 4));
///
/// // position 1 in the source domain maps to position 1 in the folded domain
/// assert_eq!(folded_domain[1], source_domain[1].exp(4));
///
/// // position 9 in the source domain also maps to position 1 in the folded domain
/// assert_eq!(folded_domain[1], source_domain[9].exp(4));
/// ```
pub fn fold_positions(
    positions: &[usize],
    source_domain_size: usize,
    folding_factor: usize,
) -> Vec<usize> {
    let target_domain_size = source_domain_size / folding_factor;

    let mut result = Vec::new();
    for position in positions {
        let position = position % target_domain_size;
        // make sure we don't record duplicated values
        if !result.contains(&position) {
            result.push(position);
        }
    }

    result
}

// HELPER FUNCTIONS
// ================================================================================================

fn get_inv_offsets<B>(domain_size: usize, domain_offset: B, folding_factor: usize) -> Vec<B>
where
    B: StarkField,
{
    let n = domain_size * folding_factor;
    let g = B::get_root_of_unity(n.ilog2());
    get_power_series_with_offset(g.inv(), domain_offset.inv(), domain_size)
}
