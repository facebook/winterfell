// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{LogUpGkrEvaluator, PeriodicTable};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

use crate::{
    comb_func, evaluate_composition_poly, EqFunction, FinalLayerProof, FinalOpeningClaim,
    MultiLinearPoly, RoundProof, SumCheckProof, SumCheckRoundClaim,
};

/// Verifies sum-check proofs, as part of the GKR proof, for all GKR layers except for the last one
/// i.e., the circuit input layer.
pub fn verify_sum_check_intermediate_layers<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    proof: &SumCheckProof<E>,
    gkr_eval_point: &[E],
    claims: &[(E, E)],
    tensored_circuit_batching_randomness: &[E],
    transcript: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<FinalOpeningClaim<E>, SumCheckVerifierError> {
    // generate challenge to batch sum-checks
    let mut concatenated_claims = Vec::with_capacity(claims.len() * 2);
    for claim in claims {
        concatenated_claims.extend_from_slice(&[claim.0, claim.1]);
    }
    transcript.reseed(H::hash_elements(&concatenated_claims));

    let r_batch: E = transcript
        .draw()
        .map_err(|_| SumCheckVerifierError::FailedToGenerateChallenge)?;

    let mut batched_claims = vec![];
    for claim in claims {
        let claim = claim.0 + claim.1 * r_batch;
        batched_claims.push(claim)
    }

    let mut full_claim = E::ZERO;
    for (circuit_id, claim) in batched_claims.iter().enumerate() {
        full_claim += *claim * tensored_circuit_batching_randomness[circuit_id]
    }
    let SumCheckProof { openings_claim, round_proofs } = proof;

    let final_round_claim = verify_rounds(full_claim, round_proofs, transcript)?;
    assert_eq!(openings_claim.eval_point, final_round_claim.eval_point);

    let mut eval_batched_circuits = E::ZERO;
    let eq = EqFunction::new(gkr_eval_point.into()).evaluate(&openings_claim.eval_point.clone());
    for (circuit_idx, openings) in openings_claim.openings.iter().enumerate() {
        let p0 = openings[0];
        let p1 = openings[1];
        let q0 = openings[2];
        let q1 = openings[3];

        eval_batched_circuits += comb_func(p0, p1, q0, q1, eq, r_batch)
            * tensored_circuit_batching_randomness[circuit_idx]
    }

    if eval_batched_circuits != final_round_claim.claim {
        assert_eq!(1, 0);
        return Err(SumCheckVerifierError::FinalEvaluationCheckFailed);
    }

    Ok(openings_claim.clone())
}

/// Sum-check verifier for the input layer.
///
/// Verifies the final sum-check proof i.e., the one for the input layer, including the final check,
/// and returns a [`FinalOpeningClaim`] to the STARK verifier in order to verify the correctness of
/// the openings.
pub fn verify_sum_check_input_layer<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    proof: &FinalLayerProof<E>,
    log_up_randomness: Vec<E>,
    gkr_eval_point: &[E],
    claim: Vec<(E, E)>,
    tensored_circuit_batching_randomness: &[E],
    transcript: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<FinalOpeningClaim<E>, SumCheckVerifierError> {
    let mut all_claims_concatenated = Vec::with_capacity(claim.len());
    for claimed_evaluation in claim.iter() {
        all_claims_concatenated.extend_from_slice(&[claimed_evaluation.0, claimed_evaluation.1]);
    }
    transcript.reseed(H::hash_elements(&all_claims_concatenated));

    // generate challenge to batch sum-checks
    let r_batch: E = transcript
        .draw()
        .map_err(|_| SumCheckVerifierError::FailedToGenerateChallenge)?;

    let mut batched_claims = vec![];
    for claimed_evaluation in claim.iter() {
        let claim = claimed_evaluation.0 + claimed_evaluation.1 * r_batch;
        batched_claims.push(claim)
    }

    let mut full_claim = E::ZERO;
    for (circuit_id, claim) in batched_claims.iter().enumerate() {
        full_claim += *claim * tensored_circuit_batching_randomness[circuit_id]
    }

    // verify the sum-check proof
    let SumCheckRoundClaim { eval_point, claim } =
        verify_rounds(full_claim, &proof.0.round_proofs, transcript)?;

    // execute the final evaluation check
    if proof.0.openings_claim.eval_point != eval_point {
        return Err(SumCheckVerifierError::WrongOpeningPoint);
    }

    let mut numerators_zero = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut numerators_one = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators_zero = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators_one = vec![E::ZERO; evaluator.get_num_fractions()];

    let trace_len = 1 << eval_point.len();
    let periodic_columns = evaluator.build_periodic_values(trace_len);
    let (periodic_columns_evaluations_zero, periodic_columns_evaluations_one) =
        evaluate_periodic_columns_at(periodic_columns, &proof.0.openings_claim.eval_point);

    let mut at_zero = Vec::with_capacity(proof.0.openings_claim.openings[0].len());
    let mut at_one = Vec::with_capacity(proof.0.openings_claim.openings[0].len());
    for ml in proof.0.openings_claim.openings[0].chunks(2) {
        at_zero.push(ml[0]);
        at_one.push(ml[1]);
    }

    evaluator.evaluate_query(
        &at_zero,
        &periodic_columns_evaluations_zero,
        &log_up_randomness,
        &mut numerators_zero,
        &mut denominators_zero,
    );
    evaluator.evaluate_query(
        &at_one,
        &periodic_columns_evaluations_one,
        &log_up_randomness,
        &mut numerators_one,
        &mut denominators_one,
    );

    let eq_nu = EqFunction::new(gkr_eval_point.into());

    let eq_nu_eval = eq_nu.evaluate(&proof.0.openings_claim.eval_point);

    let expected_evaluation = evaluate_composition_poly(
        tensored_circuit_batching_randomness,
        &numerators_zero,
        &denominators_zero,
        &numerators_one,
        &denominators_one,
        eq_nu_eval,
        r_batch,
    );

    if expected_evaluation != claim {
        assert_eq!(1, 0);
        Err(SumCheckVerifierError::FinalEvaluationCheckFailed)
    } else {
        Ok(proof.0.openings_claim.clone())
    }
}

/// Verifies a round of the sum-check protocol without executing the final check.
fn verify_rounds<E, H>(
    claim: E,
    round_proofs: &[RoundProof<E>],
    coin: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckRoundClaim<E>, SumCheckVerifierError>
where
    E: FieldElement,
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

#[derive(Debug, thiserror::Error)]
pub enum SumCheckVerifierError {
    #[error("the final evaluation check of sum-check failed")]
    FinalEvaluationCheckFailed,
    #[error("failed to generate round challenge")]
    FailedToGenerateChallenge,
    #[error("wrong opening point for the oracles")]
    WrongOpeningPoint,
}

// HELPER
// =================================================================================================

/// Evaluates periodic columns as multi-linear extensions.
fn evaluate_periodic_columns_at<E: FieldElement>(
    periodic_columns: PeriodicTable<E>,
    eval_point: &[E],
) -> (Vec<E>, Vec<E>) {
    let mut eval_point_zero = eval_point.to_vec();
    let mut eval_point_one = eval_point.to_vec();
    eval_point_zero.push(E::ZERO);
    eval_point_one.push(E::ONE);

    let mut evaluations_zero = vec![];
    let mut evaluations_one = vec![];
    for col in periodic_columns.table() {
        let ml = MultiLinearPoly::from_evaluations(col.to_vec());
        let num_variables = ml.num_variables();
        let point_zero = &eval_point_zero[eval_point_zero.len() - num_variables..];
        let point_one = &eval_point_one[eval_point_one.len() - num_variables..];

        let evaluation_zero = ml.evaluate(point_zero);
        evaluations_zero.push(evaluation_zero);
        let evaluation_one = ml.evaluate(point_one);
        evaluations_one.push(evaluation_one)
    }
    (evaluations_zero, evaluations_one)
}
