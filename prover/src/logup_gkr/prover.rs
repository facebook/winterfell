use alloc::vec::Vec;

use air::{LogUpGkrEvaluator, LogUpGkrOracle, PeriodicTable};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
use sumcheck::{
    sum_check_prove_higher_degree, sumcheck_prove_plain_batched,
    sumcheck_prove_plain_batched_serial, BeforeFinalLayerProof, CircuitOutput, EqFunction,
    FinalLayerProof, GkrCircuitProof, MultiLinearPoly, SumCheckProof,
};
use tracing::instrument;

use super::{CircuitLayerPolys, EvaluatedCircuit, GkrClaim, GkrProverError};
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
    let circuits = EvaluatedCircuit::new(main_trace, evaluator, &logup_randomness)?;

    // include the circuit output as part of the final proof
    let output_layers = circuits.output_layers().clone();

    // run the GKR prover for all layers except the input layer
    let (before_final_layer_proofs, gkr_claim, tensored_circuit_batching_randomness) =
        prove_intermediate_layers(circuits, public_coin)?;

    // build the MLEs of the relevant main trace columns
    let main_trace_mls =
        build_mls_from_main_trace_segment(evaluator.get_oracles(), main_trace.main_segment())?;
    // build the periodic table representing periodic columns as multi-linear extensions
    let periodic_table = evaluator.build_periodic_values(main_trace.main_segment().num_rows());

    // run the GKR prover for the input layer
    let final_layer_proof = prove_input_layer(
        evaluator,
        logup_randomness,
        main_trace_mls,
        periodic_table,
        gkr_claim,
        &tensored_circuit_batching_randomness,
        public_coin,
    )?;

    let mut numerators_all_circuits = vec![];
    let mut denominators_all_circuits = vec![];
    for output_layer in output_layers {
        let CircuitLayerPolys { numerators, denominators } = output_layer;
        numerators_all_circuits.push(numerators);
        denominators_all_circuits.push(denominators);
    }

    Ok(GkrCircuitProof {
        circuit_outputs: CircuitOutput {
            numerators: numerators_all_circuits,
            denominators: denominators_all_circuits,
        },
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
    tensored_batching_randomness: &[E],
    transcript: &mut C,
) -> Result<FinalLayerProof<E>, GkrProverError> {
    // parse the [GkrClaim] resulting from the previous GKR layer
    let GkrClaim {
        evaluation_point,
        claimed_evaluations_per_circuit: claimed_evaluations,
    } = claim;

    let mut all_claims_concatenated = Vec::with_capacity(claimed_evaluations.len());
    for claimed_evaluation in claimed_evaluations.iter() {
        all_claims_concatenated.extend_from_slice(&[claimed_evaluation.0, claimed_evaluation.1]);
    }
    transcript.reseed(H::hash_elements(&all_claims_concatenated));

    let r_batch = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let mut full_claim = E::ZERO;
    for (circuit_idx, claimed_evaluation) in claimed_evaluations.iter().enumerate() {
        let claim = claimed_evaluation.0 + claimed_evaluation.1 * r_batch;
        full_claim += claim * tensored_batching_randomness[circuit_idx]
    }

    let proof = sum_check_prove_higher_degree(
        evaluator,
        evaluation_point,
        full_claim,
        r_batch,
        log_up_randomness,
        multi_linear_ext_polys,
        periodic_table,
        tensored_batching_randomness,
        transcript,
    )?;

    Ok(FinalLayerProof::new(proof))
}

/// Builds the multi-linear extension polynomials needed to run the final sum-check of GKR for
/// LogUp-GKR.
#[instrument(skip_all)]
fn build_mls_from_main_trace_segment<E: FieldElement>(
    oracles: &[LogUpGkrOracle],
    main_trace: &ColMatrix<<E as FieldElement>::BaseField>,
) -> Result<Vec<MultiLinearPoly<E>>, GkrProverError> {
    let mut mls = vec![];

    for oracle in oracles {
        match oracle {
            LogUpGkrOracle::CurrentRow(index) => {
                let col = main_trace.get_column(*index);
                let values: Vec<E> = col.iter().map(|value| E::from(*value)).collect();
                let ml = MultiLinearPoly::from_evaluations(values);
                mls.push(ml)
            },
            LogUpGkrOracle::NextRow(index) => {
                let col = main_trace.get_column(*index);
                let mut values: Vec<E> = col.iter().map(|value| E::from(*value)).collect();
                values.rotate_left(1);
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
) -> Result<(BeforeFinalLayerProof<E>, GkrClaim<E>, Vec<E>), GkrProverError> {
    // absorb the circuit output layer. This corresponds to sending the four values of the output
    // layer to the verifier. The verifier then replies with a challenge `r` in order to evaluate
    // `p` and `q` at `r` as multi-linears.
    let output_layers = circuit.output_layers();

    let mut total_evaluations =
        Vec::with_capacity(output_layers[0].numerators.evaluations().len() * 2);
    for output_layer in output_layers.into_iter() {
        total_evaluations.extend_from_slice(&output_layer.numerators.evaluations());
        total_evaluations.extend_from_slice(output_layer.denominators.evaluations());
    }
    transcript.reseed(H::hash_elements(&total_evaluations));

    // generate the challenge and reduce [p0, p1, q0, q1] to [pr, qr]
    let r = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let mut claimed_evaluations = circuit.evaluate_output_layer(r);
    let num_circuits = claimed_evaluations.len();
    let log_num_circuits = num_circuits.ilog2();
    assert_eq!(1 << log_num_circuits, num_circuits);

    let mut circuit_batching_randomness: Vec<E> = Vec::with_capacity(log_num_circuits as usize);
    for _ in 0..log_num_circuits {
        let batching_r =
            transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
        circuit_batching_randomness.push(batching_r);
    }

    let tensored_circuit_batching_randomness =
        EqFunction::new(circuit_batching_randomness.into()).evaluations();

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
        let mut eq_mle = EqFunction::ml_at(evaluation_point.into());

        // run the sumcheck protocol
        let proof = sum_check_prove_num_rounds_degree_3(
            inner_layer,
            &claimed_evaluations,
            &mut eq_mle,
            &tensored_circuit_batching_randomness,
            transcript,
        )?;

        // sample a random challenge to reduce claims
        for tmp in proof.openings_claim.openings.iter() {
            transcript.reseed(H::hash_elements(tmp));
        }
        let r_layer = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;

        // reduce the claims
        for (j, claimed_opening) in proof.openings_claim.openings.iter().enumerate() {
            let p0 = claimed_opening[0];
            let p1 = claimed_opening[1];
            let q0 = claimed_opening[2];
            let q1 = claimed_opening[3];

            let reduced_claim = (p0 + r_layer * (p1 - p0), q0 + r_layer * (q1 - q0));
            claimed_evaluations[j] = reduced_claim;
        }

        // collect the randomness used for the current layer
        let mut ext = proof.openings_claim.eval_point.clone();
        ext.push(r_layer);
        evaluation_point = ext;

        layer_proofs.push(proof);
    }

    Ok((
        BeforeFinalLayerProof { proof: layer_proofs },
        GkrClaim {
            evaluation_point,
            claimed_evaluations_per_circuit: claimed_evaluations,
        },
        tensored_circuit_batching_randomness,
    ))
}

/// Runs the sum-check prover used in all but the input layer.
#[allow(clippy::too_many_arguments)]
fn sum_check_prove_num_rounds_degree_3<
    E: FieldElement,
    C: RandomCoin<Hasher = H, BaseField = E::BaseField>,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    inner_layers: Vec<CircuitLayerPolys<E>>,
    claims: &[(E, E)],
    eq: &mut MultiLinearPoly<E>,
    tensored_batching_randomness: &[E],
    transcript: &mut C,
) -> Result<SumCheckProof<E>, GkrProverError> {
    // generate challenge to batch two sumchecks
    let mut concatenated_claims = Vec::with_capacity(claims.len() * 2);
    for claim in claims {
        concatenated_claims.extend_from_slice(&[claim.0, claim.1]);
    }
    transcript.reseed(H::hash_elements(&concatenated_claims));

    let r_batch = transcript.draw().map_err(|_| GkrProverError::FailedToGenerateChallenge)?;
    let mut batched_claims = vec![];
    for claim in claims {
        let claim = claim.0 + claim.1 * r_batch;
        batched_claims.push(claim)
    }
    let proof = if inner_layers[0].numerators.num_evaluations() >= 64 {
        sumcheck_prove_plain_batched(
            &batched_claims,
            r_batch,
            inner_layers,
            eq,
            tensored_batching_randomness,
            transcript,
        )?
    } else {
        sumcheck_prove_plain_batched_serial(
            &batched_claims,
            r_batch,
            inner_layers,
            eq,
            tensored_batching_randomness,
            transcript,
        )?
    };

    Ok(proof)
}
