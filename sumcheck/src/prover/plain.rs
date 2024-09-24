// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;
use smallvec::smallvec;

use super::{CircuitLayerPolys, SumCheckProverError};
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






pub fn sumcheck_prove_plain_batched<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    claims: &[E],
    r_batch: E,
    mut inner_layers: Vec<CircuitLayerPolys<E>>,
    eq: &mut MultiLinearPoly<E>,
    tensored_batching_randomness: &[E],
    transcript: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let mut round_proofs = vec![];

    let mut challenges = vec![];

    let mut batched_claim_across_circuits = claims
        .iter()
        .zip(tensored_batching_randomness.iter())
        .fold(E::ZERO, |acc, (&claim_for_circuit_i, &randomness_for_circuit_i)| {
            acc + claim_for_circuit_i * randomness_for_circuit_i
        });

    let num_sum_check_rounds = inner_layers[0].numerators.num_variables() - 1;

    for _ in 0..num_sum_check_rounds {
        let len = inner_layers[0].numerators.num_evaluations() / 4;

        #[cfg(feature = "concurrent")]
        let (all_round_poly_eval_at_1, all_round_poly_eval_at_2, all_round_poly_eval_at_3) =
            inner_layers
                .par_iter()
                .zip(tensored_batching_randomness.par_iter())
                .fold(
                    || (E::ZERO, E::ZERO, E::ZERO),
                    |(_acc_eval_1, _acc_eval_2, _acc_eval_3), (inner_layer, batching_randomness)| {
                        let (round_poly_eval_at_1, round_poly_eval_at_2, round_poly_eval_at_3) =
                            (0..len).fold((E::ZERO, E::ZERO, E::ZERO), |(a, b, c), i| {
                                let p0_i_0 = inner_layer.numerators[2 * i];
                                let p0_i_1 = inner_layer.numerators[2 * i + 1];
                                let p1_i_0 = inner_layer.numerators[2 * (i + len)];
                                let p1_i_1 = inner_layer.numerators[2 * (i + len) + 1];
                                let q0_i_0 = inner_layer.denominators[2 * i];
                                let q0_i_1 = inner_layer.denominators[2 * i + 1];
                                let q1_i_0 = inner_layer.denominators[2 * (i + len)];
                                let q1_i_1 = inner_layer.denominators[2 * (i + len) + 1];
                                let round_poly_eval_at_1 =
                                    comb_func(p1_i_0, p1_i_1, q1_i_0, q1_i_1, eq[i + len], r_batch);

                                let p0_delta = p1_i_0 - p0_i_0;
                                let p1_delta = p1_i_1 - p0_i_1;
                                let q0_delta = q1_i_0 - q0_i_0;
                                let q1_delta = q1_i_1 - q0_i_1;
                                let eq_delta = eq[i + len] - eq[i];

                                let mut p0_eval_at_x = p1_i_0 + p0_delta;
                                let mut p1_eval_at_x = p1_i_1 + p1_delta;
                                let mut q0_eval_at_x = q1_i_0 + q0_delta;
                                let mut q1_eval_at_x = q1_i_1 + q1_delta;
                                let mut eq_evx = eq[i + len] + eq_delta;
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
                                    round_poly_eval_at_1 + a,
                                    round_poly_eval_at_2 + b,
                                    round_poly_eval_at_3 + c,
                                )
                            });

                        let tmp_round_poly_eval_at_1 = round_poly_eval_at_1 * *batching_randomness;
                        let tmp_round_poly_eval_at_2 = round_poly_eval_at_2 * *batching_randomness;
                        let tmp_round_poly_eval_at_3 = round_poly_eval_at_3 * *batching_randomness;

                        (
                            tmp_round_poly_eval_at_1,
                            tmp_round_poly_eval_at_2,
                            tmp_round_poly_eval_at_3,
                        )
                    },
                )
                .reduce(
                    || (E::ZERO, E::ZERO, E::ZERO),
                    |(a0, b0, c0), (a1, b1, c1)| (a0 + a1, b0 + b1, c0 + c1),
                );

        #[cfg(not(feature = "concurrent"))]
        let (all_round_poly_eval_at_1, all_round_poly_eval_at_2, all_round_poly_eval_at_3) =
            inner_layers.iter().zip(tensored_batching_randomness).fold(
                (E::ZERO, E::ZERO, E::ZERO),
                |(eval_poly1, eval_poly2, eval_poly3), (inner_layer, batching_randomness)| {
                    let (round_poly_eval_at_1, round_poly_eval_at_2, round_poly_eval_at_3) =
                        (0..len).fold(
                            (E::ZERO, E::ZERO, E::ZERO),
                            |(acc_point_1, acc_point_2, acc_point_3), i| {
                                let p0_i_0 = inner_layer.numerators[2 * i];
                                let p0_i_1 = inner_layer.numerators[2 * i + 1];
                                let p1_i_0 = inner_layer.numerators[2 * (i + len)];
                                let p1_i_1 = inner_layer.numerators[2 * (i + len) + 1];
                                let q0_i_0 = inner_layer.denominators[2 * i];
                                let q0_i_1 = inner_layer.denominators[2 * i + 1];
                                let q1_i_0 = inner_layer.denominators[2 * (i + len)];
                                let q1_i_1 = inner_layer.denominators[2 * (i + len) + 1];
                                let round_poly_eval_at_1 =
                                    comb_func(p1_i_0, p1_i_1, q1_i_0, q1_i_1, eq[i + len], r_batch);

                                let p0_delta = p1_i_0 - p0_i_0;
                                let p1_delta = p1_i_1 - p0_i_1;
                                let q0_delta = q1_i_0 - q0_i_0;
                                let q1_delta = q1_i_1 - q0_i_1;
                                let eq_delta = eq[i + len] - eq[i];

                                let mut p0_eval_at_x = p1_i_0 + p0_delta;
                                let mut p1_eval_at_x = p1_i_1 + p1_delta;
                                let mut q0_eval_at_x = q1_i_0 + q0_delta;
                                let mut q1_eval_at_x = q1_i_1 + q1_delta;
                                let mut eq_evx = eq[i + len] + eq_delta;
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

                    (
                        eval_poly1 + round_poly_eval_at_1 * *batching_randomness,
                        eval_poly2 + round_poly_eval_at_2 * *batching_randomness,
                        eval_poly3 + round_poly_eval_at_3 * *batching_randomness,
                    )
                },
            );

        let evals =
            smallvec![all_round_poly_eval_at_1, all_round_poly_eval_at_2, all_round_poly_eval_at_3];
        let compressed_round_poly_evals = CompressedUnivariatePolyEvals(evals);
        let compressed_round_poly =
            compressed_round_poly_evals.to_poly(batched_claim_across_circuits);

        // reseed with the s_i polynomial
        transcript.reseed(H::hash_elements(&compressed_round_poly.0));
        let round_proof = RoundProof {
            round_poly_coefs: compressed_round_poly.clone(),
        };

        let round_challenge =
            transcript.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        for inner_layer in inner_layers.iter_mut() {
            // fold each multi-linear using the round challenge
            inner_layer.numerators.bind_least_significant_variable(round_challenge);
            inner_layer.denominators.bind_least_significant_variable(round_challenge);
        }
        eq.bind_least_significant_variable(round_challenge);

        // compute the new reduced round claim
        batched_claim_across_circuits = compressed_round_poly
            .evaluate_using_claim(&batched_claim_across_circuits, &round_challenge);

        round_proofs.push(round_proof);
        challenges.push(round_challenge);
    }

    let mut openings = Vec::with_capacity(inner_layers.len());
    for inner_layer in inner_layers.iter_mut() {
        let p = inner_layer.numerators.evaluations();
        let q = inner_layer.denominators.evaluations();
        openings.push(vec![p[0], p[1], q[0], q[1]])
    }

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim { eval_point: challenges, openings },
        round_proofs,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sumcheck_prove_plain_batched_serial<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    claims: &[E],
    r_batch: E,
    mut inner_layers: Vec<CircuitLayerPolys<E>>,
    eq: &mut MultiLinearPoly<E>,
    tensored_batching_randomness: &[E],
    transcript: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let mut round_proofs = vec![];

    let mut challenges = vec![];

    let mut batched_claim_across_circuits = claims
        .iter()
        .zip(tensored_batching_randomness.iter())
        .fold(E::ZERO, |acc, (&claim_for_circuit_i, &randomness_for_circuit_i)| {
            acc + claim_for_circuit_i * randomness_for_circuit_i
        });

    let num_sum_check_rounds = inner_layers[0].numerators.num_variables() - 1;
    for _ in 0..num_sum_check_rounds {
        let mut all_round_poly_eval_at_1 = E::ZERO;
        let mut all_round_poly_eval_at_2 = E::ZERO;
        let mut all_round_poly_eval_at_3 = E::ZERO;
        let len = inner_layers[0].numerators.num_evaluations() / 4;

        for (inner_layer, batching_randomness) in
            inner_layers.iter().zip(tensored_batching_randomness)
        {
            let (round_poly_eval_at_1, round_poly_eval_at_2, round_poly_eval_at_3) = (0..len).fold(
                (E::ZERO, E::ZERO, E::ZERO),
                |(acc_point_1, acc_point_2, acc_point_3), i| {
                    let p0_i_0 = inner_layer.numerators[2 * i];
                    let p0_i_1 = inner_layer.numerators[2 * i + 1];
                    let p1_i_0 = inner_layer.numerators[2 * (i + len)];
                    let p1_i_1 = inner_layer.numerators[2 * (i + len) + 1];
                    let q0_i_0 = inner_layer.denominators[2 * i];
                    let q0_i_1 = inner_layer.denominators[2 * i + 1];
                    let q1_i_0 = inner_layer.denominators[2 * (i + len)];
                    let q1_i_1 = inner_layer.denominators[2 * (i + len) + 1];
                    let round_poly_eval_at_1 =
                        comb_func(p1_i_0, p1_i_1, q1_i_0, q1_i_1, eq[i + len], r_batch);

                    let p0_delta = p1_i_0 - p0_i_0;
                    let p1_delta = p1_i_1 - p0_i_1;
                    let q0_delta = q1_i_0 - q0_i_0;
                    let q1_delta = q1_i_1 - q0_i_1;
                    let eq_delta = eq[i + len] - eq[i];

                    let mut p0_eval_at_x = p1_i_0 + p0_delta;
                    let mut p1_eval_at_x = p1_i_1 + p1_delta;
                    let mut q0_eval_at_x = q1_i_0 + q0_delta;
                    let mut q1_eval_at_x = q1_i_1 + q1_delta;
                    let mut eq_evx = eq[i + len] + eq_delta;
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

            all_round_poly_eval_at_1 += round_poly_eval_at_1 * *batching_randomness;
            all_round_poly_eval_at_2 += round_poly_eval_at_2 * *batching_randomness;
            all_round_poly_eval_at_3 += round_poly_eval_at_3 * *batching_randomness;
        }

        let evals =
            smallvec![all_round_poly_eval_at_1, all_round_poly_eval_at_2, all_round_poly_eval_at_3];
        let compressed_round_poly_evals = CompressedUnivariatePolyEvals(evals);
        let compressed_round_poly =
            compressed_round_poly_evals.to_poly(batched_claim_across_circuits);

        // reseed with the s_i polynomial
        transcript.reseed(H::hash_elements(&compressed_round_poly.0));
        let round_proof = RoundProof {
            round_poly_coefs: compressed_round_poly.clone(),
        };

        let round_challenge =
            transcript.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        for inner_layer in inner_layers.iter_mut() {
            // fold each multi-linear using the round challenge
            inner_layer.numerators.bind_least_significant_variable(round_challenge);
            inner_layer.denominators.bind_least_significant_variable(round_challenge);
        }
        eq.bind_least_significant_variable(round_challenge);

        // compute the new reduced round claim
        batched_claim_across_circuits = compressed_round_poly
            .evaluate_using_claim(&batched_claim_across_circuits, &round_challenge);

        round_proofs.push(round_proof);
        challenges.push(round_challenge);
    }

    let mut openings = Vec::with_capacity(inner_layers.len());
    for inner_layer in inner_layers.iter_mut() {
        let p = inner_layer.numerators.evaluations();
        let q = inner_layer.denominators.evaluations();
        openings.push(vec![p[0], p[1], q[0], q[1]])
    }

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim { eval_point: challenges, openings },
        round_proofs,
    })
}
