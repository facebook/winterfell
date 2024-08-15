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
) -> Result<SumCheckRoundClaim<E>, SumCheckVerifierError>
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

        let r = coin.draw().map_err(|_| SumCheckVerifierError::FailedToGenerateChallenge)?;

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
) -> Result<FinalOpeningClaim<E>, SumCheckVerifierError> {
    // generate challenge to batch sum-checks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch: E = transcript
        .draw()
        .map_err(|_| SumCheckVerifierError::FailedToGenerateChallenge)?;

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
        return Err(SumCheckVerifierError::FinalEvaluationCheckFailed);
    }

    Ok(openings_claim.clone())
}

/// Verifies the final sum-check proof i.e., the one for the input layer, including the final check,
/// and returns a [`FinalOpeningClaim`] to the STARK verifier in order to verify the correctness of
/// the openings.
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
) -> Result<FinalOpeningClaim<E>, SumCheckVerifierError> {
    let FinalLayerProof { proof } = proof;

    // generate challenge to batch sum-checks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch: E = transcript
        .draw()
        .map_err(|_| SumCheckVerifierError::FailedToGenerateChallenge)?;

    // compute the claim for the batched sum-check
    let reduced_claim = claim.0 + claim.1 * r_batch;

    // verify the sum-check proof
    let SumCheckRoundClaim { eval_point, claim } =
        verify_rounds(reduced_claim, &proof.round_proofs, transcript)?;

    // execute the final evaluation check
    if proof.openings_claim.eval_point != eval_point {
        return Err(SumCheckVerifierError::WrongOpeningPoint);
    }

    let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];
    evaluator.evaluate_query(
        &proof.openings_claim.openings,
        &log_up_randomness,
        &mut numerators,
        &mut denominators,
    );

    let mu = evaluator.get_num_fractions().trailing_zeros() - 1;
    let (evaluation_point_mu, evaluation_point_nu) = gkr_eval_point.split_at(mu as usize);

    let eq_mu = EqFunction::new(evaluation_point_mu.to_vec()).evaluations();
    let eq_nu = EqFunction::new(evaluation_point_nu.to_vec());

    let eq_nu_eval = eq_nu.evaluate(&proof.openings_claim.eval_point);
    let expected_evaluation =
        evaluate_composition_poly(&eq_mu, &numerators, &denominators, eq_nu_eval, r_batch);

    if expected_evaluation != claim {
        Err(SumCheckVerifierError::FinalEvaluationCheckFailed)
    } else {
        Ok(proof.openings_claim.clone())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SumCheckVerifierError {
    #[error("the final evaluation check of sum-check failed")]
    FinalEvaluationCheckFailed,
    #[error("failed to generate round challenge")]
    FailedToGenerateChallenge,
    #[error("wrong opening point for the oracles")]
    WrongOpeningPoint,
}
