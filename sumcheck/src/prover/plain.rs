// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

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
/// [1]: https://eprint.iacr.org/2023/1284
#[allow(clippy::too_many_arguments)]
pub fn sumcheck_prove_plain<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    num_rounds: usize,
    claim: E,
    r_batch: E,
    p0: &mut MultiLinearPoly<E>,
    p1: &mut MultiLinearPoly<E>,
    q0: &mut MultiLinearPoly<E>,
    q1: &mut MultiLinearPoly<E>,
    eq: &mut MultiLinearPoly<E>,
    transcript: &mut C,
) -> Result<(SumCheckProof<E>, E), SumCheckProverError> {
    let mut round_proofs = vec![];

    let mut claim = claim;
    let mut challenges = vec![];
    for _ in 0..num_rounds {
        let mut eval_point_0 = E::ZERO;
        let mut eval_point_2 = E::ZERO;
        let mut eval_point_3 = E::ZERO;

        let len = p0.num_evaluations() / 2;
        for i in 0..len {
            eval_point_0 +=
                comb_func(p0[2 * i], p1[2 * i], q0[2 * i], q1[2 * i], eq[2 * i], r_batch);

            let p0_delta = p0[2 * i + 1] - p0[2 * i];
            let p1_delta = p1[2 * i + 1] - p1[2 * i];
            let q0_delta = q0[2 * i + 1] - q0[2 * i];
            let q1_delta = q1[2 * i + 1] - q1[2 * i];
            let eq_delta = eq[2 * i + 1] - eq[2 * i];

            let mut p0_evx = p0[2 * i + 1] + p0_delta;
            let mut p1_evx = p1[2 * i + 1] + p1_delta;
            let mut q0_evx = q0[2 * i + 1] + q0_delta;
            let mut q1_evx = q1[2 * i + 1] + q1_delta;
            let mut eq_evx = eq[2 * i + 1] + eq_delta;
            eval_point_2 += comb_func(p0_evx, p1_evx, q0_evx, q1_evx, eq_evx, r_batch);

            p0_evx += p0_delta;
            p1_evx += p1_delta;
            q0_evx += q0_delta;
            q1_evx += q1_delta;
            eq_evx += eq_delta;
            eval_point_3 += comb_func(p0_evx, p1_evx, q0_evx, q1_evx, eq_evx, r_batch);
        }

        let evals = vec![
            claim - eval_point_0, // Optimization applied using the claim to reduce the number of sums computed
            eval_point_2,
            eval_point_3,
        ];
        let poly = CompressedUnivariatePolyEvals(evals.into());
        let round_poly_coefs = poly.to_poly(claim);

        // reseed with the s_i polynomial
        transcript.reseed(H::hash_elements(&round_poly_coefs.0));
        let round_proof = RoundProof {
            round_poly_coefs: round_poly_coefs.clone(),
        };

        round_proofs.push(round_proof);

        let round_challenge =
            transcript.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        // compute the new reduced round claim
        let new_claim = round_poly_coefs.evaluate_using_claim(&claim, &round_challenge);

        // fold each multi-linear using the round challenge
        p0.bind_least_significant_variable(round_challenge);
        p1.bind_least_significant_variable(round_challenge);
        q0.bind_least_significant_variable(round_challenge);
        q1.bind_least_significant_variable(round_challenge);
        eq.bind_least_significant_variable(round_challenge);

        challenges.push(round_challenge);

        claim = new_claim;
    }

    Ok((
        SumCheckProof {
            openings_claim: FinalOpeningClaim {
                eval_point: challenges,
                openings: vec![p0[0], p1[0], q0[0], q1[0]],
            },
            round_proofs,
        },
        claim,
    ))
}