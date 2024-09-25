// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use smallvec::smallvec;

use super::SumCheckProverError;
use crate::{
    comb_func, CompressedUnivariatePolyEvals, FinalOpeningClaim, MultiLinearPoly, RoundProof,
    SumCheckProof,
};

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

    for _ in 0..p0.num_variables() {
        let len = p0.num_evaluations() / 2;

        #[cfg(not(feature = "concurrent"))]
        let (round_poly_eval_at_1, round_poly_eval_at_2, round_poly_eval_at_3) = (0..len).fold(
            (E::ZERO, E::ZERO, E::ZERO),
            |(acc_point_1, acc_point_2, acc_point_3), i| {
                let round_poly_eval_at_1 = comb_func(
                    p0[len + i],
                    p1[len + i],
                    q0[len + i],
                    q1[len + i],
                    eq[len + i],
                    r_batch,
                );

                let p0_delta = p0[len + i] - p0[i];
                let p1_delta = p1[len + i] - p1[i];
                let q0_delta = q0[len + i] - q0[i];
                let q1_delta = q1[len + i] - q1[i];
                let eq_delta = eq[len + i] - eq[i];

                let mut p0_eval_at_x = p0[len + i] + p0_delta;
                let mut p1_eval_at_x = p1[len + i] + p1_delta;
                let mut q0_eval_at_x = q0[len + i] + q0_delta;
                let mut q1_eval_at_x = q1[len + i] + q1_delta;
                let mut eq_evx = eq[len + i] + eq_delta;
                let round_poly_eval_at_2 = comb_func(
                    p0_eval_at_x,
                    p1_eval_at_x,
                    q0_eval_at_x,
                    q1_eval_at_x,
                    eq_evx,
                    r_batch,
                );

                p0_eval_at_x += p0_delta;
                p1_eval_at_x += p1_delta;
                q0_eval_at_x += q0_delta;
                q1_eval_at_x += q1_delta;
                eq_evx += eq_delta;
                let round_poly_eval_at_3 = comb_func(
                    p0_eval_at_x,
                    p1_eval_at_x,
                    q0_eval_at_x,
                    q1_eval_at_x,
                    eq_evx,
                    r_batch,
                );

                (
                    round_poly_eval_at_1 + acc_point_1,
                    round_poly_eval_at_2 + acc_point_2,
                    round_poly_eval_at_3 + acc_point_3,
                )
            },
        );

        #[cfg(feature = "concurrent")]
        let (round_poly_eval_at_1, round_poly_eval_at_2, round_poly_eval_at_3) = (0..len)
            .into_par_iter()
            .fold(
                || (E::ZERO, E::ZERO, E::ZERO),
                |(a, b, c), i| {
                    let round_poly_eval_at_1 = comb_func(
                        p0[len + i],
                        p1[len + i],
                        q0[len + i],
                        q1[len + i],
                        eq[len + i],
                        r_batch,
                    );

                    let p0_delta = p0[len + i] - p0[i];
                    let p1_delta = p1[len + i] - p1[i];
                    let q0_delta = q0[len + i] - q0[i];
                    let q1_delta = q1[len + i] - q1[i];
                    let eq_delta = eq[len + i] - eq[i];

                    let mut p0_eval_at_x = p0[len + i] + p0_delta;
                    let mut p1_eval_at_x = p1[len + i] + p1_delta;
                    let mut q0_eval_at_x = q0[len + i] + q0_delta;
                    let mut q1_eval_at_x = q1[len + i] + q1_delta;
                    let mut eq_evx = eq[len + i] + eq_delta;
                    let round_poly_eval_at_2 = comb_func(
                        p0_eval_at_x,
                        p1_eval_at_x,
                        q0_eval_at_x,
                        q1_eval_at_x,
                        eq_evx,
                        r_batch,
                    );

                    p0_eval_at_x += p0_delta;
                    p1_eval_at_x += p1_delta;
                    q0_eval_at_x += q0_delta;
                    q1_eval_at_x += q1_delta;
                    eq_evx += eq_delta;
                    let round_poly_eval_at_3 = comb_func(
                        p0_eval_at_x,
                        p1_eval_at_x,
                        q0_eval_at_x,
                        q1_eval_at_x,
                        eq_evx,
                        r_batch,
                    );
                    (round_poly_eval_at_1 + a, round_poly_eval_at_2 + b, round_poly_eval_at_3 + c)
                },
            )
            .reduce(
                || (E::ZERO, E::ZERO, E::ZERO),
                |(a0, b0, c0), (a1, b1, c1)| (a0 + a1, b0 + b1, c0 + c1),
            );

        let evals = smallvec![round_poly_eval_at_1, round_poly_eval_at_2, round_poly_eval_at_3];
        let compressed_round_poly_evals = CompressedUnivariatePolyEvals(evals);
        let compressed_round_poly = compressed_round_poly_evals.to_poly(claim);

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
        eq.bind_least_significant_variable(round_challenge);

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
