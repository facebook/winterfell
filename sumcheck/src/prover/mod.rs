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

fn compute_weight<E: FieldElement>(alpha: E, x: E) -> E {
    x * alpha + (E::ONE - x) * (E::ONE - alpha)
}

fn to_coefficients<E: FieldElement>(
    round_poly_evals: &mut [E],
    claim: E,
    alpha: E,
    scaling_down_factor: E,
    scaling_up_factor: E,
) -> CompressedUnivariatePoly<E> {
    let a = scaling_down_factor;
    round_poly_evals.iter_mut().for_each(|e| *e *= scaling_up_factor);

    let mut round_poly_evaluations = vec![];
    round_poly_evaluations.push(round_poly_evals[0] * compute_weight(alpha, E::ZERO) * a);
    round_poly_evaluations.push(claim - round_poly_evaluations[0]);

    for (x, eval) in round_poly_evals.iter().skip(1).enumerate() {
        round_poly_evaluations.push(*eval * compute_weight(alpha, E::from(x as u32 + 2)) * a)
    }

    let root = (E::ONE - alpha) / (E::ONE - alpha.double());

    let round_poly_coefs_alt = interpolate_equidistant_points(&round_poly_evaluations, root);

    round_poly_coefs_alt
}

fn compute_scaling_down_factors<E: FieldElement>(gkr_point: &[E]) -> Vec<E> {
    let cumulative_product: Vec<E> = gkr_point
        .iter()
        .scan(E::ONE, |acc, &x| {
            *acc = *acc * (E::ONE - x);
            Some(*acc)
        })
        .collect();
    batch_inversion(&cumulative_product)
}
