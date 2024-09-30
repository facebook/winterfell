use alloc::vec::Vec;

use air::{Air, LogUpGkrEvaluator};
use crypto::{ElementHasher, RandomCoin};
use libc_print::libc_println;
use math::FieldElement;
use sumcheck::{
    verify_sum_check_input_layer, verify_sum_check_intermediate_layers, CircuitOutput, EqFunction,
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
    let claim = evaluator.compute_claim(pub_inputs, &logup_randomness);
    let mut total_evaluations = Vec::with_capacity(numerators.len() * 4);
    let mut num_acc = E::ZERO;
    let mut den_acc = E::ONE;
    for (nums, dens) in numerators.iter().zip(denominators.iter()) {
        total_evaluations.extend_from_slice(nums.evaluations());
        total_evaluations.extend_from_slice(dens.evaluations());

        let p0 = nums.evaluations()[0];
        let p1 = nums.evaluations()[1];
        let q0 = dens.evaluations()[0];
        let q1 = dens.evaluations()[1];

        // make sure that both denominators are not equal to E::ZERO
        if q0 == E::ZERO || q1 == E::ZERO {
            return Err(VerifierError::ZeroOutputDenominator);
        }

        let cur_num = p0 * q1 + p1 * q0;
        let cur_den = q0 * q1;

        let new_num = num_acc * cur_den + den_acc * cur_num;
        let new_den = den_acc * cur_den;
        num_acc = new_num;
        den_acc = new_den;
    }
    if num_acc / den_acc != claim {
        libc_println!("num_acc {:?}", num_acc);
        libc_println!("den_acc {:?}", den_acc);
        libc_println!("num_acc / den_acc {:?}", num_acc / den_acc);
        libc_println!("claim {:?}", claim);
        return Err(VerifierError::MismatchingCircuitOutput);
    }

    transcript.reseed(H::hash_elements(&total_evaluations));
    // generate the random challenge to reduce two claims into a single claim
    let r = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

    // reduce the claim
    let mut reduced_claims = vec![];
    for (nums, dens) in numerators.iter().zip(denominators.iter()) {
        let p0 = nums.evaluations()[0];
        let p1 = nums.evaluations()[1];
        let q0 = dens.evaluations()[0];
        let q1 = dens.evaluations()[1];
        // reduce the claim
        let p_r = p0 + r * (p1 - p0);
        let q_r = q0 + r * (q1 - q0);
        let reduced_claim = (p_r, q_r);
        reduced_claims.push(reduced_claim)
    }

    let num_circuits = reduced_claims.len();
    let log_num_circuits = num_circuits.next_power_of_two().ilog2();

    let mut circuit_batching_randomness: Vec<E> = vec![];

    for _ in 0..log_num_circuits {
        let batching_r = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;
        circuit_batching_randomness.push(batching_r);
    }

    let tensored_circuit_batching_randomness =
        EqFunction::new(circuit_batching_randomness.into()).evaluations();

    // verify all GKR layers but for the last one
    let num_layers = before_final_layer_proofs.proof.len();
    let mut evaluation_point = vec![r];
    for i in 0..num_layers {
        let FinalOpeningClaim { eval_point, openings } = verify_sum_check_intermediate_layers(
            &before_final_layer_proofs.proof[i],
            &evaluation_point,
            &reduced_claims,
            &tensored_circuit_batching_randomness,
            transcript,
        )?;

        // generate the random challenge to reduce two claims into a single claim
        let mut total_openings = Vec::with_capacity(openings.len() * 4);
        for opening_circuit_i in openings.iter() {
            total_openings.extend_from_slice(opening_circuit_i);
        }
        transcript.reseed(H::hash_elements(&total_openings));
        let r_layer = transcript.draw().map_err(|_| VerifierError::FailedToGenerateChallenge)?;

        for (circuit_id, ops) in openings.iter().enumerate() {
            let p0 = ops[0];
            let p1 = ops[1];
            let q0 = ops[2];
            let q1 = ops[3];

            let reduced_claim = (p0 + r_layer * (p1 - p0), q0 + r_layer * (q1 - q0));
            reduced_claims[circuit_id] = reduced_claim;
        }

        // collect the randomness used for the current layer
        let mut ext = eval_point.clone();
        ext.push(r_layer);
        evaluation_point = ext;
    }

    // verify the proof of the final GKR layer and pass final opening claim for verification
    // to the STARK
    verify_sum_check_input_layer(
        evaluator,
        final_layer_proof,
        logup_randomness,
        &evaluation_point,
        reduced_claims,
        &tensored_circuit_batching_randomness,
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
