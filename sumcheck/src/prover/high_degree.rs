// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{LogUpGkrEvaluator, PeriodicTable};
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

use super::SumCheckProverError;
use crate::{
    comb_func, evaluate_composition_poly, CompressedUnivariatePolyEvals, EqFunction,
    FinalOpeningClaim, MultiLinearPoly, RoundProof, SumCheckProof, SumCheckRoundClaim,
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
///
/// The sum above is evaluated using a layered circuit with the equation linking the input layer
/// values $p_n$ to the next layer values $p_{n-1}$ given by the following relations
///
/// $$
/// p_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) = \sum_{w_i, y_i}
///             EQ\left(\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right),
///                  \left(w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
///                      \cdot \left( p_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
///                       \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right) +
///              p_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)  \cdot
///                 q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
/// $$
///
/// and
///
/// $$
/// q_{n-1}\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right) = \sum_{w_i, y_i}
///             EQ\left(\left(v_2, \cdots, v_{\mu}, x_1, \cdots, x_{\nu}\right),
///                  \left(w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
///                     \cdot \left( q_n\left(1, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)
///                       \cdot q_n\left(0, w_2, \cdots, w_{\mu}, y_1, \cdots, y_{\nu}\right)\right)
/// $$
///
/// and similarly for all subsequent layers.
///
/// These expressions are nothing but the equations in Section 3.2 in [1] but with the projection
/// happening at the first argument instead of the last.
///
/// We can now note a few things about the above:
///
/// 1. During the evaluation phase of the circuit, the prover needs to compute every tuple
///    $\left(p_k, q_k\right)$ for $k = n, \cdots, 1$ over the boolean hyper-cubes of
///    the appropriate sizes. In particular, the prover will have the evaluations
///    $\left(p_n, q_n\right)$ over $\{0, 1\}^{\mu + \nu}$ stored.
/// 2. Since $p_n$ and $q_n$ are linear in the first $\mu$ variables, we can directly use
///    the stored evaluations of $p_n$ and $q_n$ during the final sum-check, the one linking
///    the input layer to its next layer, for the first $\mu - 1$ rounds. This means that for
///    the first $\mu - 1$ rounds, the last sum-check protocol can be treated like the sum-checks
///    for the other layers i.e., the original degree $3$ sum-check of the LogUp-GKR paper.
/// 3. For the last $\nu$ rounds of the final sum-check, we can still use the evaluations of
///    $\left(p_k, q_k\right)$, or more precisely the result of their binding with the $\mu -1$
///    round challenges from point 2 above, in order to optimize the computation of the sum-check
///    round polynomials but due to the non-linearity of $\left(p_n, q_n\right)$ in the last $\nu$
///    variables, we will have to work with
///
/// $$
/// p_n\left(v_1, r_1, \cdots, r_{\mu - 1}, x_1, \cdots, x_{\nu}\right) = \sum_{w\in\{0, 1\}^{\mu}}
///      EQ\left(\left(v_1, r_1, \cdots, r_{\mu - 1}\right), \left(w_1, \cdots, w_{\mu}\right)\right)
///      g_{[w]}\left(f_1\left(x_1, \cdots, x_{\nu}\right), \cdots,
///                                                 f_l\left(x_1, \cdots, x_{\nu}\right)\right)
/// $$
///
/// and
///
/// $$
/// q_n\left(v_1, r_1, \cdots, r_{\mu - 1}, x_1, \cdots, x_{\nu}\right) = \sum_{w\in\{0, 1\}^{\mu}}
///     EQ\left(\left(v_1, r_1, \cdots, r_{\mu - 1}\right), \left(w_1, \cdots, w_{\mu}\right)\right)
///     h_{[w]}\left(f_1\left(x_1, \cdots, x_{\nu}\right), \cdots,
///                                                 f_l\left(x_1, \cdots, x_{\nu}\right)\right)
/// $$
///
/// where $r_i$ is the sum-check round challenges of the first $\mu - 1$ rounds.
///
/// The current function executes the last $\nu$ parts of the sum-check and uses
/// the [`LogUpGkrEvaluator`] to evaluate $g_i$ and $h_i$ during the computation of the evaluations
/// of the round polynomials.
///
/// As an optimization, the function uses the five polynomials, refered to as [`merged_mls`]:
///
/// 1. $p_n\left(0, r_1, \cdots, r_{\mu - 1}, x_1, \cdots, x_{\nu}\right)$
/// 2. $p_n\left(1, r_1, \cdots, r_{\mu - 1}, x_1, \cdots, x_{\nu}\right)$
/// 3. $q_n\left(0, r_1, \cdots, r_{\mu - 1}, x_1, \cdots, x_{\nu}\right)$
/// 4. $q_n\left(1, r_1, \cdots, r_{\mu - 1}, x_1, \cdots, x_{\nu}\right)$
/// 5. $$\left(y_1, \cdots, y_{\nu}\right) \longrightarrow
///     EQ\left(\left(t_1, \cdots, t_{\mu + \nu - 1}\right),
///     \left(r_1, \cdots, r_{\mu - 1}, y_1, \cdots, y_{\nu}\right)\right)
///    $$
///    where $t_i$ is the sum-check randomness from the previous layer.
///
///
/// [1]: https://eprint.iacr.org/2023/1284
#[allow(clippy::too_many_arguments)]
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
    periodic_table: &mut PeriodicTable<E>,
    merged_mls: &mut [MultiLinearPoly<E>],
    mls: &mut [MultiLinearPoly<E>],
    coin: &mut C,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let num_rounds = mls[0].num_variables();

    let mut round_proofs = vec![];

    // setup first round claim
    let mut current_round_claim = SumCheckRoundClaim { eval_point: vec![], claim };

    // compute, for all (w_1, \cdots, w_{\mu - 1}) in {0, 1}^{\mu - 1}:
    // EQ\left(\left(r_1, \cdots, r_{\mu - 1}\right), \left(w_1, \cdots, w_{\mu - 1}\right)\right)
    let tensored_merge_randomness = EqFunction::ml_at(rand_merge.to_vec()).evaluations().to_vec();

    // run the first round of the protocol
    let round_poly_evals = sumcheck_round(
        evaluator,
        mls,
        merged_mls,
        &log_up_randomness,
        periodic_table,
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
        // fold each periodic multi-linear using the round challenge
        periodic_table.bind_least_significant_variable(round_challenge);

        // run the i-th round of the protocol using the folded multi-linears for the new reduced
        // claim. This basically computes the s_i polynomial.
        let round_poly_evals = sumcheck_round(
            evaluator,
            mls,
            merged_mls,
            &log_up_randomness,
            periodic_table,
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
    // fold each periodic multi-linear using the last random round challenge
    periodic_table.bind_least_significant_variable(round_challenge);

    let SumCheckRoundClaim { eval_point, claim: _claim } =
        reduce_claim(&round_proofs[num_rounds - 1], current_round_claim, round_challenge);

    let openings = mls.iter_mut().map(|ml| ml.evaluations()[0]).collect();

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim { eval_point, openings },
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
    evaluator: &impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    mls: &[MultiLinearPoly<E>],
    merged_mls: &[MultiLinearPoly<E>],
    log_up_randomness: &[E],
    periodic_table: &mut PeriodicTable<E>,
    r_sum_check: E,
    tensored_merge_randomness: &[E],
) -> CompressedUnivariatePolyEvals<E> {
    let num_ml = mls.len();
    let num_vars = mls[0].num_variables();
    let num_rounds = num_vars - 1;
    let mut evals_one = vec![E::ZERO; num_ml + periodic_table.num_columns()];
    let mut evals_zero = vec![E::ZERO; num_ml + periodic_table.num_columns()];
    let mut evals_x = vec![E::ZERO; num_ml + periodic_table.num_columns()];
    let mut deltas = vec![E::ZERO; num_ml + periodic_table.num_columns()];

    let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
    let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];

    let total_evals = (0..1 << num_rounds).map(|i| {
        let mut total_evals = vec![E::ZERO; evaluator.max_degree()];

        for (j, ml) in mls.iter().enumerate() {
            evals_zero[j] = ml.evaluations()[2 * i];

            evals_one[j] = ml.evaluations()[2 * i + 1];
        }

        let eq_at_zero = merged_mls[4].evaluations()[2 * i];
        let eq_at_one = merged_mls[4].evaluations()[2 * i + 1];

        let periodic_at_zero = periodic_table.get_periodic_values(2 * i);
        let periodic_at_one = periodic_table.get_periodic_values(2 * i + 1);

        evals_zero
            .iter_mut()
            .skip(num_ml)
            .enumerate()
            .for_each(|(i, ev)| *ev = periodic_at_zero[i]);
        evals_one
            .iter_mut()
            .skip(num_ml)
            .enumerate()
            .for_each(|(i, ev)| *ev = periodic_at_one[i]);

        let p0 = merged_mls[0][2 * i + 1];
        let p1 = merged_mls[1][2 * i + 1];
        let q0 = merged_mls[2][2 * i + 1];
        let q1 = merged_mls[3][2 * i + 1];

        total_evals[0] = comb_func(p0, p1, q0, q1, eq_at_one, r_sum_check);

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
                log_up_randomness,
                &mut numerators,
                &mut denominators,
            );

            *e = evaluate_composition_poly(
                &numerators,
                &denominators,
                eq_x,
                r_sum_check,
                tensored_merge_randomness,
            );
        }

        total_evals
    });

    let evaluations = total_evals.fold(vec![E::ZERO; evaluator.max_degree()], |mut acc, evals| {
        acc.iter_mut().zip(evals.iter()).for_each(|(a, ev)| *a += *ev);
        acc
    });

    CompressedUnivariatePolyEvals(evaluations.into())
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
