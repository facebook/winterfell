// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

use super::{compute_scaling_down_factors, to_coefficients, SumCheckProverError};
use crate::{comb_func, FinalOpeningClaim, MultiLinearPoly, RoundProof, SumCheckProof};

/// Sum-check prover for non-linear multivariate polynomial of the simple LogUp-GKR.
///
/// More specifically, the following function implements the logic of the sum-check prover as
/// described in Section 3.2 in [1], that is, given verifier challenges  , the following implements
/// the sum-check prover for the following two statements
/// $$
/// p_{\nu - \kappa}\left(v_{\kappa+1}, \cdots, v_{\nu}\right) = \sum_{w_i}
///     EQ\left(\left(v_{\kappa+1}, \cdots, v_{\nu}\right), \left(w_{\kappa+1}, \cdots,
///                              w_{\nu}\right)\right) \cdot
///      \left( p_{\nu-\kappa+1}\left(1, w_{\kappa+1}, \cdots, w_{\nu}\right)  \cdot
///              q_{\nu-\kappa+1}\left(0, w_{\kappa+1}, \cdots, w_{\nu}\right) +
///     p_{\nu-\kappa+1}\left(0, w_{\kappa+1}, \cdots, w_{\nu}\right)  \cdot
///     q_{\nu-\kappa+1}\left(1, w_{\kappa+1}, \cdots, w_{\nu}\right)\right)
/// $$
///
/// and
///
/// $$
/// q_{\nu -k}\left(v_{\kappa+1}, \cdots, v_{\nu}\right) = \sum_{w_i}EQ\left(\left(v_{\kappa+1},
///  \cdots, v_{\nu}\right), \left(w_{\kappa+1}, \cdots, w_{\nu }\right)\right) \cdot
/// \left( q_{\nu-\kappa+1}\left(1, w_{\kappa+1}, \cdots, w_{\nu}\right)  \cdot
///  q_{\nu-\kappa+1}\left(0, w_{\kappa+1}, \cdots, w_{\nu}\right)\right)
/// $$
///
/// for $k = 1, \cdots, \nu - 1$  
///
/// Instead of executing two runs of the sum-check protocol, a batching randomness `r_batch` is
/// sent by the verifier at the outset in order to batch the two statments.
///
/// Note that the degree of the non-linear composition polynomial is 3.
///
/// [1]: https://eprint.iacr.org/2023/1284
#[allow(clippy::too_many_arguments)]
pub fn sumcheck_prove_plain<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    mut claim: E,
    gkr_point: &[E],
    r_batch: E,
    p: MultiLinearPoly<E>,
    q: MultiLinearPoly<E>,
    eq: &mut MultiLinearPoly<E>,
    transcript: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let mut round_proofs = vec![];

    let mut challenges = vec![];

    // construct the vector of multi-linear polynomials
    let (mut p0, mut p1) = p.project_least_significant_variable();
    let (mut q0, mut q1) = q.project_least_significant_variable();

    let num_rounds = p0.num_variables();

    let nu = gkr_point.len();
    let mut scaling_down_factors = compute_scaling_down_factors(gkr_point);
    let mut scaling_up_factor = E::ONE;

    for l in 0..num_rounds {
        let len = p0.num_evaluations() / 2;

        #[cfg(not(feature = "concurrent"))]
        let (round_poly_eval_at_0, round_poly_eval_at_2) =
            (0..len).fold((E::ZERO, E::ZERO), |(acc_point_0, acc_point_2), i| {
                let j = i << (l + 1);
                let round_poly_eval_at_0 =
                    comb_func(p0[2 * i], p1[2 * i], q0[2 * i], q1[2 * i], eq[j], r_batch);

                let p0_delta = p0[2 * i + 1] - p0[2 * i];
                let p1_delta = p1[2 * i + 1] - p1[2 * i];
                let q0_delta = q0[2 * i + 1] - q0[2 * i];
                let q1_delta = q1[2 * i + 1] - q1[2 * i];

                let p0_eval_at_x = p0[2 * i + 1] + p0_delta;
                let p1_eval_at_x = p1[2 * i + 1] + p1_delta;
                let q0_eval_at_x = q0[2 * i + 1] + q0_delta;
                let q1_eval_at_x = q1[2 * i + 1] + q1_delta;
                let round_poly_eval_at_2 = comb_func(
                    p0_eval_at_x,
                    p1_eval_at_x,
                    q0_eval_at_x,
                    q1_eval_at_x,
                    eq[j],
                    r_batch,
                );

                (round_poly_eval_at_0 + acc_point_0, round_poly_eval_at_2 + acc_point_2)
            });

        #[cfg(feature = "concurrent")]
        let (round_poly_eval_at_0, round_poly_eval_at_2) = (0..len)
            .into_par_iter()
            .fold(
                || (E::ZERO, E::ZERO),
                |(a, b), i| {
                    let j = i << (l + 1);
                    let round_poly_eval_at_0 =
                        comb_func(p0[2 * i], p1[2 * i], q0[2 * i], q1[2 * i], eq[j], r_batch);

                    let p0_delta = p0[2 * i + 1] - p0[2 * i];
                    let p1_delta = p1[2 * i + 1] - p1[2 * i];
                    let q0_delta = q0[2 * i + 1] - q0[2 * i];
                    let q1_delta = q1[2 * i + 1] - q1[2 * i];

                    let p0_eval_at_x = p0[2 * i + 1] + p0_delta;
                    let p1_eval_at_x = p1[2 * i + 1] + p1_delta;
                    let q0_eval_at_x = q0[2 * i + 1] + q0_delta;
                    let q1_eval_at_x = q1[2 * i + 1] + q1_delta;
                    let round_poly_eval_at_2 = comb_func(
                        p0_eval_at_x,
                        p1_eval_at_x,
                        q0_eval_at_x,
                        q1_eval_at_x,
                        eq[j],
                        r_batch,
                    );

                    (round_poly_eval_at_0 + a, round_poly_eval_at_2 + b)
                },
            )
            .reduce(|| (E::ZERO, E::ZERO), |(a0, b0), (a1, b1)| (a0 + a1, b0 + b1));

        let round_index = nu - p0.num_variables();
        let alpha = gkr_point[round_index];
        let scaling_down_factor = scaling_down_factors.remove(0);

        let compressed_round_poly = to_coefficients(
            &mut [round_poly_eval_at_0, round_poly_eval_at_2],
            claim,
            alpha,
            scaling_down_factor,
            scaling_up_factor,
        );

        // reseed with the s_i polynomial
        transcript.reseed(H::hash_elements(&compressed_round_poly.0));
        let round_proof = RoundProof {
            round_poly_coefs: compressed_round_poly.clone(),
        };

        let round_challenge =
            transcript.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        // fold each multi-linear using the round challenge
        p0.bind_least_significant_variable(round_challenge);
        p1.bind_least_significant_variable(round_challenge);
        q0.bind_least_significant_variable(round_challenge);
        q1.bind_least_significant_variable(round_challenge);

        // update the scaling up factor
        scaling_up_factor *=
            round_challenge * alpha + (E::ONE - round_challenge) * (E::ONE - alpha);

        // compute the new reduced round claim
        claim = compressed_round_poly.evaluate_using_claim(&claim, &round_challenge);

        round_proofs.push(round_proof);
        challenges.push(round_challenge);
    }

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim {
            eval_point: challenges,
            openings: vec![p0[0], p1[0], q0[0], q1[0]],
        },
        round_proofs,
    })
}
