// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::LogUpGkrEvaluator;
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

use crate::{
    evaluate_composition_poly, EqFunction, FinalLayerProof, FinalOpeningClaim, RoundProof,
    SumCheckProof, SumCheckRoundClaim,
};

/// Verifies a round of the sum-check protocol without executing the final check.
pub fn verify_rounds<E, C, H>(
    claim: E,
    round_proofs: &[RoundProof<E>],
    coin: &mut C,
) -> Result<SumCheckRoundClaim<E>, Error>
where
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut round_claim = claim;
    let mut evaluation_point = vec![];
    for round_proof in round_proofs {
        let round_poly_coefs = round_proof.round_poly_coefs.clone();
        coin.reseed(H::hash_elements(&round_poly_coefs.0));

        let r = coin.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

        round_claim = round_proof.round_poly_coefs.evaluate_using_claim(&round_claim, &r);
        evaluation_point.push(r);
    }

    Ok(SumCheckRoundClaim {
        eval_point: evaluation_point,
        claim: round_claim,
    })
}

/// Verifies sum-check proofs, as part of the GKR proof, for all GKR layers except for the last one
/// i.e., the circuit input layer.
pub fn verify_sum_check_intermediate_layers<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    proof: &SumCheckProof<E>,
    gkr_eval_point: &[E],
    claim: (E, E),
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, Error> {
    // generate challenge to batch sum-checks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch: E = transcript.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

    // compute the claim for the batched sum-check
    let reduced_claim = claim.0 + claim.1 * r_batch;

    let SumCheckProof { openings_claim, round_proofs } = proof;

    let final_round_claim = verify_rounds(reduced_claim, round_proofs, transcript)?;
    assert_eq!(openings_claim.eval_point, final_round_claim.eval_point);

    let p0 = openings_claim.openings[0];
    let p1 = openings_claim.openings[1];
    let q0 = openings_claim.openings[2];
    let q1 = openings_claim.openings[3];

    let eq = EqFunction::new(gkr_eval_point.to_vec()).evaluate(&openings_claim.eval_point);

    if (p0 * q1 + p1 * q0 + r_batch * q0 * q1) * eq != final_round_claim.claim {
        return Err(Error::FinalEvaluationCheckFailed);
    }

    Ok(openings_claim.clone())
}

/// Verifies the final sum-check proof of a GKR proof.
pub fn verify_sum_check_input_layer<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    proof: &FinalLayerProof<E>,
    log_up_randomness: Vec<E>,
    gkr_eval_point: &[E],
    claim: (E, E),
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, Error> {
    let FinalLayerProof { before_merge_proof, after_merge_proof } = proof;

    // generate challenge to batch sum-checks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch: E = transcript.draw().map_err(|_| Error::FailedToGenerateChallenge)?;

    // compute the claim for the batched sum-check
    let reduced_claim = claim.0 + claim.1 * r_batch;

    // verify the first half of the sum-check proof i.e., `before_merge_proof`
    let SumCheckRoundClaim { eval_point: rand_merge, claim } =
        verify_rounds(reduced_claim, before_merge_proof, transcript)?;

    // verify the second half of the sum-check proof i.e., `after_merge_proof`
    verify_sum_check_final(
        claim,
        after_merge_proof,
        rand_merge,
        r_batch,
        log_up_randomness,
        gkr_eval_point,
        evaluator,
        transcript,
    )
}

/// Verifies the second sum-check proof for the input layer, including the final check, and returns
/// a [`FinalOpeningClaim`] to the STARK verifier in order to verify the correctness of
/// the openings.
#[allow(clippy::too_many_arguments)]
fn verify_sum_check_final<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    claim: E,
    after_merge_proof: &SumCheckProof<E>,
    rand_merge: Vec<E>,
    r_batch: E,
    log_up_randomness: Vec<E>,
    gkr_eval_point: &[E],
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, Error> {
    let SumCheckProof { openings_claim, round_proofs } = after_merge_proof;

    let SumCheckRoundClaim {
        eval_point: evaluation_point,
        claim: claimed_evaluation,
    } = verify_rounds(claim, round_proofs, transcript)?;

    if openings_claim.eval_point != evaluation_point {
        return Err(Error::WrongOpeningPoint);
    }

    let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];

    evaluator.evaluate_query(
        &openings_claim.openings,
        &log_up_randomness,
        &mut numerators,
        &mut denominators,
    );

    let lagrange_ker = EqFunction::new(gkr_eval_point.to_vec());
    let mut gkr_point = rand_merge.clone();

    gkr_point.extend_from_slice(&openings_claim.eval_point.clone());
    let eq_eval = lagrange_ker.evaluate(&gkr_point);
    let tensored_merge_randomness = EqFunction::ml_at(rand_merge.to_vec()).evaluations().to_vec();
    let expected_evaluation = evaluate_composition_poly(
        &numerators,
        &denominators,
        eq_eval,
        r_batch,
        &tensored_merge_randomness,
    );

    if expected_evaluation != claimed_evaluation {
        Err(Error::FinalEvaluationCheckFailed)
    } else {
        Ok(openings_claim.clone())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the final evaluation check of sum-check failed")]
    FinalEvaluationCheckFailed,
    #[error("failed to generate round challenge")]
    FailedToGenerateChallenge,
    #[error("wrong opening point for the oracles")]
    WrongOpeningPoint,
}
