use alloc::vec::Vec;

use air::{Air, LogUpGkrEvaluator};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
use sumcheck::{
    verify_sum_check_input_layer, verify_sum_check_intermediate_layers, CircuitOutput,
    FinalOpeningClaim, GkrCircuitProof, SumCheckVerifierError,
};

/// Verifies the validity of a GKR proof for a LogUp-GKR relation.
pub fn verify_gkr<
    A: Air,
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    pub_inputs: &A::PublicInputs,
    proof: &GkrCircuitProof<E>,
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField, PublicInputs = A::PublicInputs>,
    transcript: &mut C,
) -> Result<FinalOpeningClaim<E>, VerifierError> {
    let num_logup_random_values = evaluator.get_num_rand_values();
    let mut logup_randomness: Vec<E> = Vec::with_capacity(num_logup_random_values);

    for _ in 0..num_logup_random_values {
        logup_randomness.push(transcript.draw().expect("failed to generate randomness"));
    }

    let GkrCircuitProof {
        circuit_outputs,
        before_final_layer_proofs,
        final_layer_proof,
    } = proof;

    let CircuitOutput { numerators, denominators } = circuit_outputs;
    let p0 = numerators.evaluations()[0];
    let p1 = numerators.evaluations()[1];
    let q0 = denominators.evaluations()[0];
    let q1 = denominators.evaluations()[1];

    // make sure that both denominators are not equal to E::ZERO
    if q0 == E::ZERO || q1 == E::ZERO {
        return Err(VerifierError::ZeroOutputDenominator);
    }

    // check that the output matches the expected `claim`
    let claim = evaluator.compute_claim(pub_inputs, &logup_randomness);
    if (p0 * q1 + p1 * q0) / (q0 * q1) != claim {
        return Err(VerifierError::MismatchingCircuitOutput);
    }

    // generate the random challenge to reduce two claims into a single claim
    let mut evaluations = numerators.evaluations().to_vec();
    evaluations.extend_from_slice(denominators.evaluations());
    transcript.reseed(H::hash_elements(&evaluations));
    let r = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

    // reduce the claim
    let p_r = p0 + r * (p1 - p0);
    let q_r = q0 + r * (q1 - q0);
    let mut reduced_claim = (p_r, q_r);

    // verify all GKR layers but for the last one
    let num_layers = before_final_layer_proofs.proof.len();
    let mut evaluation_point = vec![r];
    for i in 0..num_layers {
        let FinalOpeningClaim { eval_point, openings } = verify_sum_check_intermediate_layers(
            &before_final_layer_proofs.proof[i],
            &evaluation_point,
            reduced_claim,
            transcript,
        )?;

        // generate the random challenge to reduce two claims into a single claim
        transcript.reseed(H::hash_elements(&openings));
        let r_layer = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

        let p0 = openings[0];
        let p1 = openings[1];
        let q0 = openings[2];
        let q1 = openings[3];
        reduced_claim = (p0 + r_layer * (p1 - p0), q0 + r_layer * (q1 - q0));

        // collect the randomness used for the current layer
        let rand_sumcheck = eval_point;
        let mut ext = vec![r_layer];
        ext.extend_from_slice(&rand_sumcheck);
        evaluation_point = ext;
    }

    // verify the proof of the final GKR layer and pass final opening claim for verification
    // to the STARK
    verify_sum_check_input_layer(
        evaluator,
        final_layer_proof,
        logup_randomness,
        &evaluation_point,
        reduced_claim,
        transcript,
    )
    .map_err(VerifierError::FailedToVerifySumCheck)
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("one of the claimed circuit denominators is zero")]
    ZeroOutputDenominator,
    #[error("the output of the fraction circuit is not equal to the expected value")]
    MismatchingCircuitOutput,
    #[error("failed to generate the random challenge")]
    FailedToGenerateChallenge,
    #[error("failed to verify the sum-check proof")]
    FailedToVerifySumCheck(#[from] SumCheckVerifierError),
}

// UNIVARIATE IOP FOR MULTI-LINEAR EVALUATION
// ===============================================================================================

/// Generates the batching randomness used to batch a number of multi-linear evaluation claims.
///
/// This is the $\lambda$ randomness in section 5.2 in [1] but using different random values for
/// each term instead of powers of a single random element.
///
/// [1]: https://eprint.iacr.org/2023/1284
pub fn generate_gkr_randomness<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    final_opening_claim: FinalOpeningClaim<E>,
    oracles: &[LogUpGkrOracle<E::BaseField>],
    public_coin: &mut C,
) -> GkrData<E> {
    let FinalOpeningClaim { eval_point, openings } = final_opening_claim;

    public_coin.reseed(H::hash_elements(&openings));

    let mut batching_randomness = Vec::with_capacity(openings.len() - 1);
    for _ in 0..openings.len() - 1 {
        batching_randomness.push(public_coin.draw().expect("failed to generate randomness"))
    }

    GkrData::new(
        LagrangeKernelRandElements::new(eval_point),
        batching_randomness,
        openings,
        oracles.to_vec(),
    )
}
