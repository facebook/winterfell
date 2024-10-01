use alloc::vec::Vec;

use air::{LogUpGkrEvaluator, LogUpGkrOracle, PeriodicTable};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
use sumcheck::{
    sum_check_prove_higher_degree, sumcheck_prove_plain, BeforeFinalLayerProof, CircuitOutput,
    EqFunction, FinalLayerProof, GkrCircuitProof, MultiLinearPoly, SumCheckProof,
};
use tracing::instrument;
#[cfg(feature = "concurrent")]
use utils::rayon::prelude::*;
use utils::{iter, iter_mut, uninit_vector};

use super::{reduce_layer_claim, CircuitLayerPolys, EvaluatedCircuit, GkrClaim, GkrProverError};
use crate::{matrix::ColMatrix, Trace};

// PROVER
// ================================================================================================

/// Evaluates and proves a fractional sum circuit given a set of composition polynomials.
///
/// For the input layer of the circuit, each individual component of the quadruple
/// [p_0, p_1, q_0, q_1] is of the form:
///
/// m(z_0, ... , z_{μ - 1}, x_0, ... , x_{ν - 1}) = \sum_{y ∈ {0,1}^μ} EQ(z, y) * g_{[y]}(f_0(x_0,
/// ... , x_{ν - 1}), ... , f_{κ - 1}(x_0, ... , x_{ν
/// - 1}))
///
/// where:
///
/// 1. μ is the log_2 of the number of different numerator/denominator expressions divided by two.
/// 2. [y] := \sum_{j = 0}^{μ - 1} y_j * 2^j
/// 3. κ is the number of multi-linears (i.e., main trace columns) involved in the computation of
///    the circuit (i.e., virtual bus).
/// 4. ν is the log_2 of the trace length.
///
/// The above `m` is usually referred to as the merge of the individual composed multi-linear
/// polynomials  g_{[y]}(f_0(x_0, ... , x_{ν - 1}), ... , f_{κ - 1}(x_0, ... , x_{ν - 1})).
///
/// The composition polynomials `g` are provided as inputs and then used in order to compute the
/// evaluations of each of the four merge polynomials over {0, 1}^{μ + ν}. The resulting evaluations
/// are then used in order to evaluate the circuit. At this point, the GKR protocol is used to prove
/// the correctness of circuit evaluation. It should be noted that the input layer, which
/// corresponds to the last layer treated by the GKR protocol, is handled differently from the other
/// layers. More specifically, the sum-check protocol used for the input layer is composed of two
/// sum-check protocols, the first one works directly with the evaluations of the `m`'s over {0,
/// 1}^{μ + ν} and runs for μ - 1 rounds. After these μ - 1 rounds, and using the resulting [`RoundClaim`],
/// we run the second and final sum-check protocol for ν rounds on the composed multi-linear
/// polynomial given by
///
/// \sum_{y ∈ {0,1}^μ} EQ(ρ', y) * g_{[y]}(f_0(x_0, ... , x_{ν - 1}), ... , f_{κ - 1}(x_0, ... ,
/// x_{ν - 1}))
///
/// where ρ' is the randomness sampled during the first sum-check protocol.
///
/// As part of the final sum-check protocol, the openings {f_j(ρ)} are provided as part of a
/// [`FinalOpeningClaim`]. This latter claim will be proven by the STARK prover later on using the
/// auxiliary trace.
#[instrument(skip_all)]
pub fn prove_gkr<E: FieldElement>(
    main_trace: &impl Trace<BaseField = E::BaseField>,
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
) -> Result<GkrCircuitProof<E>, GkrProverError> {
    let num_logup_random_values = evaluator.get_num_rand_values();
    let mut logup_randomness: Vec<E> = Vec::with_capacity(num_logup_random_values);

    for _ in 0..num_logup_random_values {
        logup_randomness.push(public_coin.draw().expect("failed to generate randomness"));
    }

    // evaluate the GKR fractional sum circuit
    let circuit = EvaluatedCircuit::new(main_trace, evaluator, &logup_randomness)?;

    // include the circuit output as part of the final proof
    let CircuitLayerPolys { numerators, denominators } = circuit.output_layer().clone();

    // run the GKR prover for all layers except the input layer
    let (before_final_layer_proofs, gkr_claim) = prove_intermediate_layers(circuit, public_coin)?;

    // build the MLEs of the relevant main trace columns
    let main_trace_mls =
        build_mle_from_main_trace_segment(evaluator.get_oracles(), main_trace.main_segment())?;
    // build the periodic table representing periodic columns as multi-linear extensions
    let periodic_table = evaluator.build_periodic_values();

    // run the GKR prover for the input layer
    let final_layer_proof = prove_input_layer(
        evaluator,
        logup_randomness,
        main_trace_mls,
        periodic_table,
        gkr_claim,
        public_coin,
    )?;

    Ok(GkrCircuitProof {
        circuit_outputs: CircuitOutput { numerators, denominators },
        before_final_layer_proofs,
        final_layer_proof,
    })
}

/// Proves the final GKR layer which corresponds to the input circuit layer.
#[instrument(skip_all)]
fn prove_input_layer<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = E::BaseField>,
    log_up_randomness: Vec<E>,
    multi_linear_ext_polys: Vec<MultiLinearPoly<E>>,
    periodic_table: PeriodicTable<E>,
    claim: GkrClaim<E>,
    transcript: &mut C,
) -> Result<FinalLayerProof<E>, GkrProverError> {
    // parse the [GkrClaim] resulting from the previous GKR layer
    let GkrClaim { evaluation_point, claimed_evaluation } = claim;

    transcript.reseed(H::hash_elements(&[claimed_evaluation.0, claimed_evaluation.1]));
    let r_batch = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let claim = claimed_evaluation.0 + claimed_evaluation.1 * r_batch;

    let proof = sum_check_prove_higher_degree(
        evaluator,
        evaluation_point,
        claim,
        r_batch,
        log_up_randomness,
        multi_linear_ext_polys,
        periodic_table,
        transcript,
    )?;

    Ok(FinalLayerProof::new(proof))
}

/// Builds the multi-linear extension polynomials needed to run the final sum-check of GKR for
/// LogUp-GKR.
#[instrument(skip_all)]
fn build_mle_from_main_trace_segment<E: FieldElement>(
    oracles: &[LogUpGkrOracle],
    main_trace: &ColMatrix<<E as FieldElement>::BaseField>,
) -> Result<Vec<MultiLinearPoly<E>>, GkrProverError> {
    let mut mls = Vec::with_capacity(oracles.len());

    for oracle in oracles {
        match oracle {
            LogUpGkrOracle::CurrentRow(index) => {
                let col = main_trace.get_column(*index);
                let values: Vec<E> = iter!(col).map(|value| E::from(*value)).collect();
                let ml = MultiLinearPoly::from_evaluations(values);
                mls.push(ml)
            },
            LogUpGkrOracle::NextRow(index) => {
                let col = main_trace.get_column(*index);

                let mut values: Vec<E> = unsafe { uninit_vector(col.len()) };
                values[col.len() - 1] = E::from(col[0]);
                iter_mut!(&mut values[..col.len() - 1])
                    .enumerate()
                    .for_each(|(i, value)| *value = E::from(col[i + 1]));
                let ml = MultiLinearPoly::from_evaluations(values);
                mls.push(ml)
            },
        };
    }

    Ok(mls)
}

/// Proves all GKR layers except for input layer.
#[instrument(skip_all)]
fn prove_intermediate_layers<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    circuit: EvaluatedCircuit<E>,
    transcript: &mut C,
) -> Result<(BeforeFinalLayerProof<E>, GkrClaim<E>), GkrProverError> {
    // absorb the circuit output layer. This corresponds to sending the four values of the output
    // layer to the verifier. The verifier then replies with a challenge `r` in order to evaluate
    // `p` and `q` at `r` as multi-linears.
    let CircuitLayerPolys { numerators, denominators } = circuit.output_layer();
    let mut evaluations = numerators.evaluations().to_vec();
    evaluations.extend_from_slice(denominators.evaluations());
    transcript.reseed(H::hash_elements(&evaluations));

    // generate the challenge and reduce [p0, p1, q0, q1] to [pr, qr]
    let r = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let mut claimed_evaluation = circuit.evaluate_output_layer(r);

    let mut layer_proofs: Vec<SumCheckProof<E>> = Vec::new();
    let mut evaluation_point = vec![r];

    // Loop over all inner layers, from output to input.
    //
    // In a layered circuit, each layer is defined in terms of its predecessor. The first inner
    // layer (starting from the output layer) is the first layer that has a predecessor. Here, we
    // loop over all inner layers in order to iteratively reduce a layer in terms of its successor
    // layer. Note that we don't include the input layer, since its predecessor layer will be
    // reduced in terms of the input layer separately in `prove_final_circuit_layer`.
    for inner_layer in circuit.layers().into_iter().skip(1).rev().skip(1) {
        // construct the Lagrange kernel evaluated at the previous GKR round randomness
        let mut eq_mle = EqFunction::ml_at(evaluation_point.clone().into());

        let (numerators, denominators) = inner_layer.into_numerators_denominators();

        // run the sumcheck protocol
        let proof = sum_check_prove_num_rounds_degree_3(
            claimed_evaluation,
            &evaluation_point,
            numerators,
            denominators,
            &mut eq_mle,
            transcript,
        )?;

        // sample a random challenge to reduce claims
        transcript.reseed(H::hash_elements(&proof.openings_claim.openings));
        let r_layer = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;

        // reduce the claim
        claimed_evaluation = {
            let left_numerators_opening = proof.openings_claim.openings[0];
            let right_numerators_opening = proof.openings_claim.openings[1];
            let left_denominators_opening = proof.openings_claim.openings[2];
            let right_denominators_opening = proof.openings_claim.openings[3];

            reduce_layer_claim(
                left_numerators_opening,
                right_numerators_opening,
                left_denominators_opening,
                right_denominators_opening,
                r_layer,
            )
        };

        // collect the randomness used for the current layer
        let mut ext = vec![r_layer];
        ext.extend_from_slice(&proof.openings_claim.eval_point);
        evaluation_point = ext;

        layer_proofs.push(proof);
    }

    Ok((
        BeforeFinalLayerProof { proof: layer_proofs },
        GkrClaim { evaluation_point, claimed_evaluation },
    ))
}

/// Runs the sum-check prover used in all but the input layer.
#[allow(clippy::too_many_arguments)]
fn sum_check_prove_num_rounds_degree_3<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    claim: (E, E),
    evaluation_point: &[E],
    p: MultiLinearPoly<E>,
    q: MultiLinearPoly<E>,
    eq: &mut MultiLinearPoly<E>,
    transcript: &mut C,
) -> Result<SumCheckProof<E>, GkrProverError> {
    // generate challenge to batch two sumchecks
    transcript.reseed(H::hash_elements(&[claim.0, claim.1]));
    let r_batch = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let claim = claim.0 + claim.1 * r_batch;

    let proof = sumcheck_prove_plain(claim, evaluation_point, r_batch, p, q, eq, transcript)?;

    Ok(proof)
}
