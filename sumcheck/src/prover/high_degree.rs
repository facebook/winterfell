// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{LogUpGkrEvaluator, PeriodicTable};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

use super::SumCheckProverError;
use crate::{
    evaluate_composition_poly, CompressedUnivariatePolyEvals, EqFunction, FinalOpeningClaim,
    MultiLinearPoly, RoundProof, SumCheckProof, SumCheckRoundClaim,
};

/// A sum-check prover for the input layer which can accommodate non-linear expressions in
/// the numerators of the LogUp relation.
///
/// The LogUp-GKR protocol in [1] is an IOP for the following statement
///
/// $$
/// \sum_{v_i, x_i} \frac{p_n\left(v_1, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right)}
///                         {q_n\left(v_1, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right)} = C
/// $$
///
/// where:
///
/// $$
/// p_n\left(v_1, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) =
///     \sum_{w\in\{0, 1\}^\mu} EQ\left(\left(v_1, \cdots, v_{\mu}\right),
///                              \left(w_1, \cdots, w_{\mu}\right)\right)
///      g_{[w]}\left(f_1\left(x_1, \cdots, x_{\nu}\right),
///                                 \cdots, f_l\left(x_1, \cdots, x_{\nu}\right)\right)
/// $$
///
/// and  
///
/// $$
/// q_n\left(v_1, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) =
///     \sum_{w\in\{0, 1\}^\mu} EQ\left(\left(v_1, \cdots, v_{\mu}\right),
///                              \left(w_1, \cdots, w_{\mu}\right)\right)
///      h_{[w]}\left(f_1\left(x_1, \cdots, x_{\nu}\right),
///                                 \cdots, f_l\left(x_1, \cdots, x_{\nu}\right)\right)
/// $$
///
/// and
///
/// 1. $f_i$ are multi-linears.
/// 2. ${[w]} := \sum_i w_i \cdot 2^i$ and $w := (w_1, \cdots, w_{\mu})$.
/// 3. $h_{j}$ and $g_{j}$ are multi-variate polynomials for $j = 0, \cdots, 2^{\mu} - 1$.
/// 4. $n := \nu + \mu$
/// 5. $\\B_{\gamma} := \{0, 1\}^{\gamma}$ for positive integer $\gamma$.
///
/// The sum above is evaluated using a layered circuit with the equation linking the input layer
/// values $p_n$ to the next layer values $p_{n-1}$ given by the following relations
///
/// $$
/// p_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) = \sum_{w_i, y_i}
/// EQ\left(\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right),
/// \left(w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
/// \cdot \left( p_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
/// \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right) +
/// p_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)  \cdot
/// q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
/// $$
///
/// and
///
/// $$
/// q_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) = \sum_{w_i, y_i}
/// EQ\left(\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right),
/// \left(w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
/// \cdot \left( q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
/// \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
/// $$
///
/// and similarly for all subsequent layers.
///
/// By the properties of the $EQ$ function, we can write the above as follows:
///
/// $$
/// p_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) = \sum_{y_i}
/// EQ\left(\left(x_1, \cdots, x_{\nu}\right),
/// \left(y_1, \cdots, y_{\nu}\right)\right)
/// \left( \sum_{w_i} EQ\left(\left(v_2, \cdots, v_{\mu}\right),
/// \left(w_2, \cdots, w_{\mu}\right)\right)
/// \cdot \left( p_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
/// \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right) +
/// p_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)  \cdot
/// q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right) \right)
/// $$
///
/// and
///
/// $$
/// q_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) = \sum_{y_i}
/// EQ\left(\left(x_1, \cdots, x_{\nu}\right),
/// \left(y_1, \cdots, y_{\nu}\right)\right)
/// \left( \sum_{w_i} EQ\left(\left(v_2, \cdots, v_{\mu}\right)\right)
/// \cdot q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
/// \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right) \right)
/// $$
///
/// These expressions are nothing but the equations in Section 3.2 in [1] but with the projection
/// happening in the first argument instead of the last one.
/// The current function is then tasked with running a batched sum-check protocol for
///
/// $$
/// p_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) =
/// \sum_{y\in\\B_{\nu}} G(y_{1}, ..., y_{\nu})
/// $$
///
/// and
///
/// $$
/// q_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) =
/// \sum_{y\in\\B_{\nu}} H\left(y_1, \cdots, y_{\nu} \right)
/// $$
///
/// where
///
/// $$
/// G := \left( \left(y_1, \cdots, y_{\nu}\right) \longrightarrow
/// EQ\left(\left(x_1, \cdots, x_{\nu}\right),
/// \left(y_1, \cdots, y_{\nu}\right)\right)
/// \left( \sum_{w_i} EQ\left(\left(v_2, \cdots, v_{\mu}\right),
/// \left(w_2, \cdots, w_{\mu}\right)\right)
/// \cdot \left( p_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
/// \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right) +
/// p_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)  \cdot
/// q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right) \right)
/// \right)
/// $$
///
/// and
///
/// $$
/// H := \left( \left(y_1, \cdots, y_{\nu}\right) \longrightarrow
/// EQ\left(\left(x_1, \cdots, x_{\nu}\right),
/// \left(y_1, \cdots, y_{\nu}\right)\right)
/// \left( \sum_{w_i} EQ\left(\left(v_2, \cdots, v_{\mu}\right)\right)
/// \cdot q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
/// \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right) \right)
/// \right)
/// $$
///
/// [1]: https://eprint.iacr.org/2023/1284
#[allow(clippy::too_many_arguments)]
pub fn sum_check_prove_higher_degree<
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
>(
    evaluator: &impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    evaluation_point: Vec<E>,
    claim: E,
    r_sum_check: E,
    log_up_randomness: Vec<E>,
    mut mls: Vec<MultiLinearPoly<E>>,
    mut periodic_table: PeriodicTable<E>,
    tensored_circuits_batching: &[E],
    coin: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let num_rounds = mls[0].num_variables() - 1;

    let mut round_proofs = vec![];

    let mut eq_mle = EqFunction::ml_at(evaluation_point.clone().into());
    // setup first round claim
    let mut current_round_claim = SumCheckRoundClaim { eval_point: vec![], claim };

    // run the first round of the protocol
    let round_poly_evals = sumcheck_round(
        &tensored_circuits_batching,
        evaluator,
        &eq_mle,
        &mls,
        &periodic_table,
        &log_up_randomness,
        r_sum_check,
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
        eq_mle.bind_least_significant_variable(round_challenge);

        // fold each periodic multi-linear using the round challenge
        periodic_table.bind_least_significant_variable(round_challenge);

        // run the i-th round of the protocol using the folded multi-linears for the new reduced
        // claim. This basically computes the s_i polynomial.
        let round_poly_evals = sumcheck_round(
            &tensored_circuits_batching,
            evaluator,
            &eq_mle,
            &mls,
            &periodic_table,
            &log_up_randomness,
            r_sum_check,
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

    // fold each periodic multi-linear using the round challenge
    periodic_table.bind_least_significant_variable(round_challenge);

    let SumCheckRoundClaim { eval_point, claim: _claim } =
        reduce_claim(&round_proofs[num_rounds - 1], current_round_claim, round_challenge);

    let openings: Vec<E> = mls
        .into_iter()
        .flat_map(|ml| [ml.evaluations()[0], ml.evaluations()[1]])
        .collect();

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim { eval_point, openings: vec![openings] },
        round_proofs,
    })
}

/// Computes the polynomial
///
/// $$
/// s_i(X_i) := \sum_{(x_{i + 1},\cdots, x_{\nu - 1})
///                                  w(r_0,\cdots, r_{i - 1}, X_i, x_{i + 1}, \cdots, x_{\nu - 1}).
/// $$
///
/// where
///
/// $$
/// w(x_0,\cdots, x_{\nu - 1}) := g(f_0((x_0,\cdots, x_{\nu - 1})),
///                                                       \cdots , f_c((x_0,\cdots, x_{\nu - 1}))).
/// $$
///
/// where `g` is the expression defined in the documentation of [`sum_check_prove_higher_degree`]
///
/// Given a degree bound `d_max` for all variables, it suffices to compute the evaluations of `s_i`
/// at `d_max + 1` points. Given that $s_{i}(0) = s_{i}(1) - s_{i - 1}(r_{i - 1})$ it is sufficient
/// to compute the evaluations on only `d_max` points.
///
/// The algorithm works by iterating over the variables $(x_{i + 1}, \cdots, x_{\nu - 1})$ in
/// ${0, 1}^{\nu - 1 - i}$. For each such tuple, we store the evaluations of the (folded)
/// multi-linears at $(0, x_{i + 1}, \cdots, x_{\nu - 1})$ and
/// $(1, x_{i + 1}, \cdots, x_{\nu - 1})$ in two arrays, `evals_zero` and `evals_one`.
/// Using `evals_one`, remember that we optimize evaluating at 0 away, we get the first evaluation
/// i.e., $s_i(1)$.
///
/// For the remaining evaluations, we use the fact that the folded `f_i` is multi-linear and hence
/// we can write
///
/// $$
///     f_i(X_i, x_{i + 1}, \cdots, x_{\nu - 1}) =
///        (1 - X_i) . f_i(0, x_{i + 1}, \cdots, x_{\nu - 1}) +
///        X_i . f_i(1, x_{i + 1}, \cdots, x_{\nu - 1})
/// $$
///
/// Note that we omitted writing the folding randomness for readability.
/// Since the evaluation domain is $\{0, 1, ... , d_max\}$, we can compute the evaluations based on
/// the previous one using only additions. This is the purpose of `deltas`, to hold the increments
/// added to each multi-linear to compute the evaluation at the next point, and `evals_x` to hold
/// the current evaluation at $x$ in $\{2, ... , d_max\}$.
fn sumcheck_round<E: FieldElement>(
    eq_mu: &[E],
    evaluator: &impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    eq_ml: &MultiLinearPoly<E>,
    mls: &[MultiLinearPoly<E>],
    periodic_table: &PeriodicTable<E>,
    log_up_randomness: &[E],
    r_sum_check: E,
) -> CompressedUnivariatePolyEvals<E> {
    let num_mls = mls.len();
    let num_periodic = periodic_table.num_columns();
    let num_vars = mls[0].num_variables();
    let num_rounds = num_vars - 1 - 1;

    #[cfg(not(feature = "concurrent"))]
    let evaluations = {
        let mut evals_one_zero = vec![E::ZERO; num_mls];
        let mut evals_one_one = vec![E::ZERO; num_mls];
        let mut evals_zero_zero = vec![E::ZERO; num_mls];
        let mut evals_zero_one = vec![E::ZERO; num_mls];

        let mut evals_x_zero = vec![E::ZERO; num_mls];
        let mut evals_x_one = vec![E::ZERO; num_mls];

        let mut evals_periodic_zero_zero = vec![E::ZERO; num_periodic];
        let mut evals_periodic_zero_one = vec![E::ZERO; num_periodic];
        let mut evals_periodic_one_zero = vec![E::ZERO; num_periodic];
        let mut evals_periodic_one_one = vec![E::ZERO; num_periodic];

        let mut evals_periodic_x_zero = vec![E::ZERO; num_periodic];
        let mut evals_periodic_x_one = vec![E::ZERO; num_periodic];

        let mut eq_x = E::ZERO;

        let mut deltas_zero = vec![E::ZERO; num_mls];
        let mut deltas_one = vec![E::ZERO; num_mls];
        let mut deltas_periodic_zero = vec![E::ZERO; num_periodic];
        let mut deltas_periodic_one = vec![E::ZERO; num_periodic];
        let mut eq_delta = E::ZERO;

        let mut numerators_zero = vec![E::ZERO; evaluator.get_num_fractions()];
        let mut denominators_zero = vec![E::ZERO; evaluator.get_num_fractions()];
        let mut numerators_one = vec![E::ZERO; evaluator.get_num_fractions()];
        let mut denominators_one = vec![E::ZERO; evaluator.get_num_fractions()];
        (0..1 << num_rounds)
            .map(|i| {
                let mut total_evals = vec![E::ZERO; evaluator.max_degree()];
                for (j, ml) in mls.iter().enumerate() {
                    evals_zero_zero[j] = ml.evaluations()[2 * i];
                    evals_zero_one[j] = ml.evaluations()[2 * i + 1];
                    evals_one_zero[j] = ml.evaluations()[2 * i + 2 * (1 << num_rounds)];
                    evals_one_one[j] = ml.evaluations()[2 * i + 2 * (1 << num_rounds) + 1];
                }
                let eq_at_zero = eq_ml.evaluations()[i];
                let eq_at_one = eq_ml.evaluations()[i + (1 << num_rounds)];

                // add evaluation of periodic columns
                periodic_table.fill_periodic_values_at(2 * i, &mut evals_periodic_zero_zero);
                periodic_table.fill_periodic_values_at(2 * i + 1, &mut evals_periodic_zero_one);
                periodic_table.fill_periodic_values_at(
                    2 * i + 2 * (1 << num_rounds),
                    &mut evals_periodic_one_zero,
                );
                periodic_table.fill_periodic_values_at(
                    2 * i + 2 * (1 << num_rounds) + 1,
                    &mut evals_periodic_one_one,
                );

                // compute the evaluation at 1
                evaluator.evaluate_query(
                    &evals_one_zero,
                    &evals_periodic_one_zero,
                    log_up_randomness,
                    &mut numerators_zero,
                    &mut denominators_zero,
                );
                evaluator.evaluate_query(
                    &evals_one_one,
                    &evals_periodic_one_one,
                    log_up_randomness,
                    &mut numerators_one,
                    &mut denominators_one,
                );
                total_evals[0] = evaluate_composition_poly(
                    eq_mu,
                    &numerators_zero,
                    &denominators_zero,
                    &numerators_one,
                    &denominators_one,
                    eq_at_one,
                    r_sum_check,
                );

                // compute the evaluations at 2, ..., d_max points
                for i in 0..num_mls {
                    deltas_zero[i] = evals_one_zero[i] - evals_zero_zero[i];
                    evals_x_zero[i] = evals_one_zero[i];
                    deltas_one[i] = evals_one_one[i] - evals_zero_one[i];
                    evals_x_one[i] = evals_one_one[i];
                }
                for i in 0..num_periodic {
                    deltas_periodic_zero[i] =
                        evals_periodic_one_zero[i] - evals_periodic_zero_zero[i];
                    evals_periodic_x_zero[i] = evals_periodic_one_zero[i];
                    deltas_periodic_one[i] = evals_periodic_one_one[i] - evals_periodic_zero_one[i];
                    evals_periodic_x_one[i] = evals_periodic_one_one[i];
                }
                eq_delta = eq_at_one - eq_at_zero;
                eq_x = eq_at_one;

                for e in total_evals.iter_mut().skip(1) {
                    evals_x_zero.iter_mut().zip(deltas_zero.iter()).for_each(|(evx, delta)| {
                        *evx += *delta;
                    });
                    evals_periodic_x_zero.iter_mut().zip(deltas_periodic_zero.iter()).for_each(
                        |(evx, delta)| {
                            *evx += *delta;
                        },
                    );
                    evals_x_one.iter_mut().zip(deltas_one.iter()).for_each(|(evx, delta)| {
                        *evx += *delta;
                    });
                    evals_periodic_x_one.iter_mut().zip(deltas_periodic_one.iter()).for_each(
                        |(evx, delta)| {
                            *evx += *delta;
                        },
                    );
                    eq_x += eq_delta;

                    evaluator.evaluate_query(
                        &evals_x_zero,
                        &evals_periodic_x_zero,
                        log_up_randomness,
                        &mut numerators_zero,
                        &mut denominators_zero,
                    );
                    evaluator.evaluate_query(
                        &evals_x_one,
                        &evals_periodic_x_one,
                        log_up_randomness,
                        &mut numerators_one,
                        &mut denominators_one,
                    );
                    *e = evaluate_composition_poly(
                        eq_mu,
                        &numerators_zero,
                        &denominators_zero,
                        &numerators_one,
                        &denominators_one,
                        eq_x,
                        r_sum_check,
                    );
                }

                total_evals
            })
            .fold(vec![E::ZERO; evaluator.max_degree()], |mut acc, poly_eval| {
                acc.iter_mut().zip(poly_eval.iter()).for_each(|(a, b)| {
                    *a += *b;
                });
                acc
            })
    };

    #[cfg(feature = "concurrent")]
    let evaluations = (0..1 << num_rounds)
        .into_par_iter()
        .fold(
            || {
                (
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; evaluator.get_num_fractions()],
                    vec![E::ZERO; evaluator.get_num_fractions()],
                    vec![E::ZERO; evaluator.get_num_fractions()],
                    vec![E::ZERO; evaluator.get_num_fractions()],
                    vec![E::ZERO; evaluator.max_degree()],
                )
            },
            |(
                mut evals_one_zero,
                mut evals_one_one,
                mut evals_zero_zero,
                mut evals_zero_one,
                mut evals_x_zero,
                mut evals_x_one,
                mut evals_periodic_zero_zero,
                mut evals_periodic_zero_one,
                mut evals_periodic_one_zero,
                mut evals_periodic_one_one,
                mut evals_periodic_x_zero,
                mut evals_periodic_x_one,
                mut deltas_zero,
                mut deltas_one,
                mut deltas_periodic_zero,
                mut deltas_periodic_one,
                mut numerators_zero,
                mut numerators_one,
                mut denominators_zero,
                mut denominators_one,
                mut poly_evals,
            ),
             i| {
                for (j, ml) in mls.iter().enumerate() {
                    evals_zero_zero[j] = ml.evaluations()[2 * i];
                    evals_zero_one[j] = ml.evaluations()[2 * i + 1];
                    evals_one_zero[j] = ml.evaluations()[2 * i + 2 * (1 << num_rounds)];
                    evals_one_one[j] = ml.evaluations()[2 * i + 2 * (1 << num_rounds) + 1];
                }

                let eq_at_zero = eq_ml.evaluations()[i];
                let eq_at_one = eq_ml.evaluations()[i + (1 << num_rounds)];

                // add evaluation of periodic columns
                periodic_table.fill_periodic_values_at(2 * i, &mut evals_periodic_zero_zero);
                periodic_table.fill_periodic_values_at(2 * i + 1, &mut evals_periodic_zero_one);
                periodic_table.fill_periodic_values_at(
                    2 * i + 2 * (1 << num_rounds),
                    &mut evals_periodic_one_zero,
                );
                periodic_table.fill_periodic_values_at(
                    2 * i + 2 * (1 << num_rounds) + 1,
                    &mut evals_periodic_one_one,
                );

                // compute the evaluation at 1
                evaluator.evaluate_query(
                    &evals_one_zero,
                    &evals_periodic_one_zero,
                    log_up_randomness,
                    &mut numerators_zero,
                    &mut denominators_zero,
                );
                evaluator.evaluate_query(
                    &evals_one_one,
                    &evals_periodic_one_one,
                    log_up_randomness,
                    &mut numerators_one,
                    &mut denominators_one,
                );
                poly_evals[0] += evaluate_composition_poly(
                    eq_mu,
                    &numerators_zero,
                    &denominators_zero,
                    &numerators_one,
                    &denominators_one,
                    eq_at_one,
                    r_sum_check,
                );

                // compute the evaluations at 2, ..., d_max points
                for i in 0..num_mls {
                    deltas_zero[i] = evals_one_zero[i] - evals_zero_zero[i];
                    evals_x_zero[i] = evals_one_zero[i];
                    deltas_one[i] = evals_one_one[i] - evals_zero_one[i];
                    evals_x_one[i] = evals_one_one[i];
                }
                for i in 0..num_periodic {
                    deltas_periodic_zero[i] =
                        evals_periodic_one_zero[i] - evals_periodic_zero_zero[i];
                    evals_periodic_x_zero[i] = evals_periodic_one_zero[i];
                    deltas_periodic_one[i] = evals_periodic_one_one[i] - evals_periodic_zero_one[i];
                    evals_periodic_x_one[i] = evals_periodic_one_one[i];
                }
                let eq_delta = eq_at_one - eq_at_zero;
                let mut eq_x = eq_at_one;

                for e in poly_evals.iter_mut().skip(1) {
                    evals_x_zero.iter_mut().zip(deltas_zero.iter()).for_each(|(evx, delta)| {
                        *evx += *delta;
                    });
                    evals_periodic_x_zero.iter_mut().zip(deltas_periodic_zero.iter()).for_each(
                        |(evx, delta)| {
                            *evx += *delta;
                        },
                    );
                    evals_x_one.iter_mut().zip(deltas_one.iter()).for_each(|(evx, delta)| {
                        *evx += *delta;
                    });
                    evals_periodic_x_one.iter_mut().zip(deltas_periodic_one.iter()).for_each(
                        |(evx, delta)| {
                            *evx += *delta;
                        },
                    );
                    eq_x += eq_delta;

                    evaluator.evaluate_query(
                        &evals_x_zero,
                        &evals_periodic_x_zero,
                        log_up_randomness,
                        &mut numerators_zero,
                        &mut denominators_zero,
                    );
                    evaluator.evaluate_query(
                        &evals_x_one,
                        &evals_periodic_x_one,
                        log_up_randomness,
                        &mut numerators_one,
                        &mut denominators_one,
                    );
                    *e += evaluate_composition_poly(
                        eq_mu,
                        &numerators_zero,
                        &denominators_zero,
                        &numerators_one,
                        &denominators_one,
                        eq_x,
                        r_sum_check,
                    );
                }

                (
                    evals_one_zero,
                    evals_one_one,
                    evals_zero_zero,
                    evals_zero_one,
                    evals_x_zero,
                    evals_x_one,
                    evals_periodic_zero_zero,
                    evals_periodic_zero_one,
                    evals_periodic_one_zero,
                    evals_periodic_one_one,
                    evals_periodic_x_zero,
                    evals_periodic_x_one,
                    deltas_zero,
                    deltas_one,
                    deltas_periodic_zero,
                    deltas_periodic_one,
                    numerators_zero,
                    numerators_one,
                    denominators_zero,
                    denominators_one,
                    poly_evals,
                )
            },
        )
        .map(|(.., poly_evals)| poly_evals)
        .reduce(
            || vec![E::ZERO; evaluator.max_degree()],
            |mut acc, poly_eval| {
                acc.iter_mut().zip(poly_eval.iter()).for_each(|(a, b)| {
                    *a += *b;
                });
                acc
            },
        );

    CompressedUnivariatePolyEvals(evaluations.into())
}

/// Reduces an old claim to a new claim using the round challenge.
fn reduce_claim<E: FieldElement>(
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
