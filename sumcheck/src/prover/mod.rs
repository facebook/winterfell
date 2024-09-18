// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

mod high_degree;
use alloc::vec::Vec;

pub use high_degree::sum_check_prove_higher_degree;

mod plain;
use math::{batch_inversion, FieldElement};
pub use plain::sumcheck_prove_plain;

mod error;
pub use error::SumCheckProverError;

use crate::{univariate::interpolate_equidistant_points, CompressedUnivariatePoly};

/// Takes the evaluation of the polynomial $v_{i+1}^{'}(X)$ defined by
///
/// $$v_{i+1}^{'}(X) =  \sum_{x} Eq\left( \left( \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left( x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$$
///
/// and computes the interpolation of the $v_{i+1}(X)$ defined by
///
/// $$
/// v_{i+1}(X) = v_{i+1}^{'}(X) \frac{Eq\left( \left(\alpha_0, \cdots, \alpha_{i - 1} \right);
/// \left( r_0, \cdots, r_{i-1} \right) \right)}{Eq\left( \left( \alpha_{0}, \cdots, \alpha_{i} \right);
/// \left(0, \cdots, 0\right) \right)} \cdot  Eq\left( \alpha_i ; X \right)
/// $$
///
/// The function returns a `CompressedUnivariatePoly` instead of the full list of coefficients.
fn to_coefficients<E: FieldElement>(
    round_poly_evals: &mut [E],
    claim: E,
    alpha: E,
    scaling_down_factor: E,
    scaling_up_factor: E,
) -> CompressedUnivariatePoly<E> {
    let a = scaling_down_factor;
    round_poly_evals.iter_mut().for_each(|e| *e *= scaling_up_factor);

    let mut round_poly_evaluations = Vec::with_capacity(round_poly_evals.len() + 1);
    round_poly_evaluations.push(round_poly_evals[0] * compute_weight(alpha, E::ZERO) * a);
    round_poly_evaluations.push(claim - round_poly_evaluations[0]);

    for (x, eval) in round_poly_evals.iter().skip(1).enumerate() {
        round_poly_evaluations.push(*eval * compute_weight(alpha, E::from(x as u32 + 2)) * a)
    }

    let root = (E::ONE - alpha) / (E::ONE - alpha.double());

    interpolate_equidistant_points(&round_poly_evaluations, root)
}

/// Computes
///
/// $$
/// Eq\left( \left( \alpha_{0}, \cdots, \alpha_{i} \right);
/// \left(0, \cdots, 0\right) \right)
/// $$
///
/// given $(\alpha_0, \cdots, \alpha_{\nu - 1})$ for all $i$ in $0, \cdots, \nu - 1$.
fn compute_scaling_down_factors<E: FieldElement>(gkr_point: &[E]) -> Vec<E> {
    let cumulative_product: Vec<E> = gkr_point
        .iter()
        .scan(E::ONE, |acc, &x| {
            *acc *= E::ONE - x;
            Some(*acc)
        })
        .collect();
    batch_inversion(&cumulative_product)
}

/// Computes $EQ(x; \alpha)$.
fn compute_weight<E: FieldElement>(alpha: E, x: E) -> E {
    x * alpha + (E::ONE - x) * (E::ONE - alpha)
}
