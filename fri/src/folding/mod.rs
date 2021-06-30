// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

use math::{
    batch_inversion,
    fft::{get_inv_twiddles, serial_fft},
    get_power_series_with_offset, polynom, FieldElement, StarkField,
};
use utils::{iter_mut, uninit_vector};

// DEGREE-RESPECTING PROJECTION
// ================================================================================================
/// Applies degree-respecting projection to the `evaluations` reducing the degree of evaluations
/// by N. For N = 4, this is equivalent to the following:
/// - Let `evaluations` contain the evaluations of polynomial f(x) of degree k
/// - Group coefficients of f so that f(x) = a(x) + x * b(x) + x^2 * c(x) + x^3 * d(x)
/// - Compute random linear combination of a, b, c, d as:
///   f'(x) = a + alpha * b + alpha^2 * c + alpha^3 * d, where alpha is a random coefficient
/// - evaluate f'(x) on a domain which consists of x^4 from the original domain (and thus is
///   1/4 the size)
/// note: to compute an x in the new domain, we need 4 values from the old domain:
/// x^{1/4}, x^{2/4}, x^{3/4}, x
pub fn apply_drp<B, E, const N: usize>(values: &[[E; N]], domain_offset: B, alpha: E) -> Vec<E>
where
    B: StarkField,
    E: FieldElement<BaseField = B>,
{
    // build offset inverses and twiddles used during polynomial interpolation
    let inv_offsets = get_inv_offsets(values.len(), domain_offset, N);
    let inv_twiddles = get_inv_twiddles::<B>(N);
    let len_offset = E::inv((N as u64).into());

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

// HELPER FUNCTIONS
// ================================================================================================

fn get_inv_offsets<B>(domain_size: usize, domain_offset: B, folding_factor: usize) -> Vec<B>
where
    B: StarkField,
{
    let n = domain_size * folding_factor;
    let g = B::get_root_of_unity(n.trailing_zeros());
    let offsets = get_power_series_with_offset(g, domain_offset, domain_size);

    batch_inversion(&offsets)
}
