// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::LogUpGkrEvaluator;
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

use crate::{
    evaluate_composition_poly,
    utils::{CompressedUnivariatePolyEvals, EqFunction, MultiLinearPoly},
    FinalOpeningClaim, RoundProof, SumCheckProof, SumCheckRoundClaim,
};

mod error;
pub use error::SumCheckProverError;

/// A sum-check prover for the input layer which can accommodate non-linear expressions in
/// the numerators of the LogUp relation.
pub fn sum_check_prove_higher_degree<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    claim: E,
    r_sum_check: E,
    rand_merge: Vec<E>,
    log_up_randomness: Vec<E>,
    merged_mls: &mut Vec<MultiLinearPoly<E>>,
    mls: &mut Vec<MultiLinearPoly<E>>,
    coin: &mut C,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let num_rounds = mls[0].num_variables();

    let mut round_proofs = vec![];

    // setup first round claim
    let mut current_round_claim = SumCheckRoundClaim { eval_point: vec![], claim };
    let tensored_merge_randomness = EqFunction::ml_at(rand_merge.to_vec()).evaluations().to_vec();

    // run the first round of the protocol
    let round_poly_evals = sumcheck_round(
        evaluator.clone(),
        mls,
        &merged_mls,
        &log_up_randomness,
        r_sum_check,
        &tensored_merge_randomness,
    );
    let round_poly_coefs = round_poly_evals.to_poly(current_round_claim.claim);

    // reseed with the s_0 polynomial
    coin.reseed(H::hash_elements(&round_poly_coefs.0));
    round_proofs.push(RoundProof { round_poly_coefs });

    for i in 1..num_rounds {
        // generate random challenge r_i for the i-th round
        let round_challenge =
            coin.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        // compute the new reduced round claim
        let new_round_claim =
            reduce_claim(&round_proofs[i - 1], current_round_claim, round_challenge);

        // fold each multi-linear using the round challenge
        mls.iter_mut()
            .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

        // fold each merged multi-linear using the round challenge
        merged_mls
            .iter_mut()
            .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

        // run the i-th round of the protocol using the folded multi-linears for the new reduced
        // claim. This basically computes the s_i polynomial.
        let round_poly_evals = sumcheck_round(
            evaluator.clone(),
            mls,
            merged_mls,
            &log_up_randomness,
            r_sum_check,
            &tensored_merge_randomness,
        );

        // update the claim
        current_round_claim = new_round_claim;

        let round_poly_coefs = round_poly_evals.to_poly(current_round_claim.claim);

        // reseed with the s_i polynomial
        coin.reseed(H::hash_elements(&round_poly_coefs.0));
        let round_proof = RoundProof { round_poly_coefs };
        round_proofs.push(round_proof);
    }

    // generate the last random challenge
    let round_challenge =
        coin.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

    // fold each multi-linear using the last random round challenge
    mls.iter_mut()
        .for_each(|ml| ml.bind_least_significant_variable(round_challenge));
    // fold each merged multi-linear using the last random round challenge
    merged_mls
        .iter_mut()
        .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

    let SumCheckRoundClaim { eval_point, claim: _claim } =
        reduce_claim(&round_proofs[num_rounds - 1], current_round_claim, round_challenge);

    let openings = mls.iter_mut().map(|ml| ml.evaluations()[0]).collect();

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim { eval_point, openings },
        round_proofs,
    })
}

fn sumcheck_round<E: FieldElement>(
    evaluator: impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    mls: &[MultiLinearPoly<E>],
    merged_mls: &[MultiLinearPoly<E>],
    log_up_randomness: &[E],
    r_sum_check: E,
    tensored_merge_randomness: &[E],
) -> CompressedUnivariatePolyEvals<E> {
    let num_ml = mls.len();
    let num_vars = mls[0].num_variables();
    let num_rounds = num_vars - 1;
    let mut evals_one = vec![E::ZERO; num_ml];
    let mut evals_zero = vec![E::ZERO; num_ml];
    let mut evals_x = vec![E::ZERO; num_ml];

    let mut deltas = vec![E::ZERO; num_ml];

    let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];

    let total_evals = (0..1 << num_rounds).map(|i| {
        let mut total_evals = vec![E::ZERO; evaluator.max_degree() as usize];

        for (j, ml) in mls.iter().enumerate() {
            evals_zero[j] = ml.evaluations()[2 * i];

            evals_one[j] = ml.evaluations()[2 * i + 1];
        }

        let eq_at_zero = merged_mls[4].evaluations()[2 * i];
        let eq_at_one = merged_mls[4].evaluations()[2 * i + 1];

        let p0 = merged_mls[0][2 * i + 1];
        let p1 = merged_mls[1][2 * i + 1];
        let q0 = merged_mls[2][2 * i + 1];
        let q1 = merged_mls[3][2 * i + 1];

        total_evals[0] = comb_func(&p0, &p1, &q0, &q1, &eq_at_one, &r_sum_check);

        evals_zero
            .iter()
            .zip(evals_one.iter().zip(deltas.iter_mut().zip(evals_x.iter_mut())))
            .for_each(|(a0, (a1, (delta, evx)))| {
                *delta = *a1 - *a0;
                *evx = *a1;
            });
        let eq_delta = eq_at_one - eq_at_zero;
        let mut eq_x = eq_at_one;

        for e in total_evals.iter_mut().skip(1) {
            evals_x.iter_mut().zip(deltas.iter()).for_each(|(evx, delta)| {
                *evx += *delta;
            });
            eq_x += eq_delta;

            evaluator.evaluate_query(
                &evals_x,
                &log_up_randomness,
                &mut numerators,
                &mut denominators,
            );

            *e = evaluate_composition_poly(
                &numerators,
                &denominators,
                eq_x,
                r_sum_check,
                &tensored_merge_randomness,
            );
        }

        total_evals
    });

    let evaluations =
        total_evals.fold(vec![E::ZERO; evaluator.max_degree() as usize], |mut acc, evals| {
            acc.iter_mut().zip(evals.iter()).for_each(|(a, ev)| *a += *ev);
            acc
        });

    CompressedUnivariatePolyEvals(evaluations)
}

/// Sum-check prover for non-linear multivariate polynomial of the simple LogUp-GKR.
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
                comb_func(&p0[2 * i], &p1[2 * i], &q0[2 * i], &q1[2 * i], &eq[2 * i], &r_batch);
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
            eval_point_2 += comb_func(&p0_evx, &p1_evx, &q0_evx, &q1_evx, &eq_evx, &r_batch);

            p0_evx += p0_delta;
            p1_evx += p1_delta;
            q0_evx += q0_delta;
            q1_evx += q1_delta;
            eq_evx += eq_delta;

            eval_point_3 += comb_func(&p0_evx, &p1_evx, &q0_evx, &q1_evx, &eq_evx, &r_batch);
        }

        let evals = vec![
            claim - eval_point_0, // Optimization applied using the claim to reduce the number of sums computed
            eval_point_2,
            eval_point_3,
        ];
        let poly = CompressedUnivariatePolyEvals(evals);
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

/// The non-linear composition polynomial of the LogUp-GKR protocol.
///
/// This is the result of batching the `p_k` and `q_k` of section 3.2 in
/// https://eprint.iacr.org/2023/1284.pdf.
fn comb_func<E: FieldElement>(p0: &E, p1: &E, q0: &E, q1: &E, eq: &E, r_batch: &E) -> E {
    (*p0 * *q1 + *p1 * *q0 + *r_batch * *q0 * *q1) * *eq
}

/// Reduces an old claim to a new claim using the round challenge.
pub fn reduce_claim<E: FieldElement>(
    current_poly: &RoundProof<E>,
    current_round_claim: SumCheckRoundClaim<E>,
    round_challenge: E,
) -> SumCheckRoundClaim<E> {
    // evaluate the round polynomial at the round challenge to obtain the new claim
    let new_claim = current_poly
        .round_poly_coefs
        .evaluate_using_claim(&current_round_claim.claim, &round_challenge);

    // update the evaluation point using the round challenge
    let mut new_partial_eval_point = current_round_claim.eval_point;
    new_partial_eval_point.push(round_challenge);

    SumCheckRoundClaim {
        eval_point: new_partial_eval_point,
        claim: new_claim,
    }
}
