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

use super::{compute_scaling_down_factors, to_coefficients, SumCheckProverError};
use crate::{
    evaluate_composition_poly, EqFunction, FinalOpeningClaim, MultiLinearPoly, RoundProof,
    SumCheckProof, SumCheckRoundClaim,
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
///
/// We now discuss a further optimization due to [2]. Suppose that we have a sum-check statment of
/// the following form:
///
/// $$v_0=\sum_{x}Eq\left(\left(\alpha_0,\cdots,\alpha_{\nu - 1}\right);\left( x_0, \cdots, x_{\nu - 1}\right)\right)
///         C\left( x_0, \cdots, x_{\nu - 1}   \right)$$
///
/// Then during round $i + 1$ of sum-check, the prover needs to send the following polynomial
///
/// $$v_{i+1}(X)=\sum_{x}Eq\left(\left(\alpha_0,\cdots,\alpha_{i - 1},\alpha_i, \alpha_{i+1},\cdots\alpha_{\nu - 1} \right);
/// \left( r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$$
///
/// We can write $v_{i+1}(X)$ as:
///
/// $$v_{i+1}(X)=Eq\left(\left(\alpha_0,\cdots,\alpha_{i - 1} \right);\left(r_0,\cdots,r_{i-1}\right)\right)
/// \cdot Eq\left(\alpha_i ;X\right)\sum_{x}Eq\left(\left(\alpha_{i+1},\cdots\alpha_{\nu - 1}\right);\left( x_{i+1}, \cdots x_{\nu - 1}\right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$$
///
/// This means that $v_{i+1}(X)$ is the product of:
///
/// 1. A constant polynomial: $Eq\left( \left(\alpha_0, \cdots, \alpha_{i - 1} \right);\left( r_0, \cdots, r_{i-1} \right) \right)$
/// 2. A linear polynomial: $Eq\left( \alpha_i ; X \right)$
/// 3. A high degree polynomial: $\sum_{x}
///    Eq\left( \left( \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);\left( x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
///    C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$
///
/// The advantage of the above decomposition is that the prover when computing $v_{i+1}(X)$ needs to sum over
///
/// $$
/// Eq\left( \left( \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);\left( x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)
/// $$
///
/// instead of
///
/// $$
/// Eq\left( \left(\alpha_0, \cdots, \alpha_{i - 1}, \alpha_i, \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left( r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)
/// $$
///
/// which has the advantage of being of degree $1$ less and hence requires less work on the part of the prover.
///
/// Thus, the prover computes the following polynomial
///
/// $$v_{i+1}^{'}(X) =  \sum_{x} Eq\left( \left( \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left( x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$$
///
/// and then scales it in order to get
///
/// $$
/// v_{i+1}(X) = v_{i+1}^{'}(X) Eq\left( \left(\alpha_0, \cdots, \alpha_{i - 1} \right);
/// \left( r_0, \cdots, r_{i-1} \right) \right) \cdot  Eq\left( \alpha_i ; X \right)
/// $$
///
/// As the prover computes $v_{i+1}^{'}(X)$ in evaluation form and hence also $v_{i+1}(X)$, this
/// means that due to the degrees being off by $1$, the prover uses we can use the linear factor
/// in order to obtain an extra evaluation point in order to be able to interpolate $v_{i+1}(X)$.
/// More precisely, we can get a root of $$v_{i+1}(X) = 0$$ by solving $$Eq\left( \alpha_i ; X \right) = 0$$
/// The latter equation has as solution $$\mathsf{r} = \frac{1 - \alpha}{1 - 2\cdot\alpha}$$
/// which is, except with negligible probability, an evaluation point not in the original
/// evaluation set and hence the prover is able to interpolate $v_{i+1}(X)$ and send it to
/// the verifier.
///
/// Note that in order to avoid having to compute $\{Eq\left( \left( \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left( x_{i+1}, \cdots x_{\nu - 1}   \right) \right)\}$ from $\{Eq\left( \left( \alpha_{i}, \cdots \alpha_{\nu - 1} \right);
/// \left( x_{i}, \cdots x_{\nu - 1}   \right) \right)\}$, or vice versa, we can write
///
/// $$v_{i+1}^{'}(X) =  \sum_{x} Eq\left( \left( \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left( x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$$
///
/// as
///
/// $$v_{i+1}^{'}(X) = \frac{1}{Eq\left( \left( \alpha_{0}, \cdots, \alpha_{i} \right);
/// \left(0, \cdots, 0\right) \right)}  \sum_{x}
/// Eq\left( \left( \alpha_{0}, \cdots, \alpha_{i}, \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left(0, \cdots, 0, x_{i+1}, \cdots x_{\nu - 1}   \right) \right)
/// C\left(  r_0, \cdots, r_{i-1}, X, x_{i+1}, \cdots x_{\nu - 1}   \right)$$
///
/// Thus, $\{Eq\left( \left( \alpha_{0}, \cdots, \alpha_{i}, \alpha_{i+1}, \cdots \alpha_{\nu - 1} \right);
/// \left(0, \cdots, 0, x_{i+1}, \cdots x_{\nu - 1}   \right) \right)\}$ can be read from
/// $\{Eq\left( \left( \alpha_{0}, \cdots, \alpha_{\nu - 1} \right);\left(x_{0}, \cdots x_{\nu - 1}   \right) \right)\}$
/// directly, at the cost of the relation between  $v_{i+1}^{'}(X)$ and $v_{i+1}(X)$ becoming
///
/// $$
/// v_{i+1}(X) = v_{i+1}^{'}(X) \frac{Eq\left( \left(\alpha_0, \cdots, \alpha_{i - 1} \right);
/// \left( r_0, \cdots, r_{i-1} \right) \right)}{Eq\left( \left( \alpha_{0}, \cdots, \alpha_{i} \right);
/// \left(0, \cdots, 0\right) \right)} \cdot  Eq\left( \alpha_i ; X \right)
/// $$
///
///
/// [1]: https://eprint.iacr.org/2023/1284
/// [2]: https://eprint.iacr.org/2024/108
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
    coin: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let num_rounds = mls[0].num_variables();

    let mut round_proofs = vec![];

    // split the evaluation point into two points of dimension mu and nu, respectively
    let mu = evaluator.get_num_fractions().trailing_zeros() - 1;
    let (evaluation_point_mu, evaluation_point_nu) = evaluation_point.split_at(mu as usize);
    let eq_mu = EqFunction::ml_at(evaluation_point_mu.into()).evaluations().to_vec();
    let eq_nu = EqFunction::ml_at(evaluation_point_nu.into());

    // setup first round claim
    let mut current_round_claim = SumCheckRoundClaim { eval_point: vec![], claim };

    // run the first round of the protocol
    let mut round_poly_evals = sumcheck_round(
        0,
        &eq_mu,
        evaluator,
        &eq_nu,
        &mls,
        &periodic_table,
        &log_up_randomness,
        r_sum_check,
    );

    // this will hold `Eq((\alpha_0, \cdots, \alpha_{i - 1});(r_0, \cdots, r_{i-1}))`
    let mut scaling_up_factor = E::ONE;
    // this will hold `Eq((\alpha_{0}, \cdots, \alpha_{i}); (0, \cdots, 0))` for all `i`
    let scaling_down_factors = compute_scaling_down_factors(evaluation_point_nu);
    // this `\alpha_i`
    let mut alpha = evaluation_point_nu[0];
    let scaling_down_factor = scaling_down_factors[0];
    let round_poly_coefs = to_coefficients(
        &mut round_poly_evals,
        current_round_claim.claim,
        alpha,
        scaling_down_factor,
        scaling_up_factor,
    );

    // reseed with the s_0 polynomial
    coin.reseed(H::hash_elements(&round_poly_coefs.0));
    round_proofs.push(RoundProof { round_poly_coefs });

    for i in 1..num_rounds {
        // generate random challenge r_i for the i-th round
        let round_challenge =
            coin.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        // update `scaling_up_factor`
        alpha = evaluation_point_nu[evaluation_point_nu.len() - mls[0].num_variables()];
        scaling_up_factor *=
            round_challenge * alpha + (E::ONE - round_challenge) * (E::ONE - alpha);

        // compute the new reduced round claim
        let new_round_claim =
            reduce_claim(&round_proofs[i - 1], current_round_claim, round_challenge);

        // fold each multi-linear using the round challenge
        mls.iter_mut()
            .for_each(|ml| ml.bind_least_significant_variable(round_challenge));

        // fold each periodic multi-linear using the round challenge
        periodic_table.bind_least_significant_variable(round_challenge);

        // run the i-th round of the protocol using the folded multi-linears for the new reduced
        // claim. This basically computes the s_i polynomial.
        let mut round_poly_evals = sumcheck_round(
            i,
            &eq_mu,
            evaluator,
            &eq_nu,
            &mls,
            &periodic_table,
            &log_up_randomness,
            r_sum_check,
        );

        // update the claim
        current_round_claim = new_round_claim;

        let alpha = evaluation_point_nu[i];
        let scaling_down_factor = scaling_down_factors[i];
        let round_poly_coefs = to_coefficients(
            &mut round_poly_evals,
            current_round_claim.claim,
            alpha,
            scaling_down_factor,
            scaling_up_factor,
        );

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
#[allow(clippy::too_many_arguments)]
fn sumcheck_round<E: FieldElement>(
    sum_check_round: usize,
    eq_mu: &[E],
    evaluator: &impl LogUpGkrEvaluator<BaseField = <E as FieldElement>::BaseField>,
    eq_ml: &MultiLinearPoly<E>,
    mls: &[MultiLinearPoly<E>],
    periodic_table: &PeriodicTable<E>,
    log_up_randomness: &[E],
    r_sum_check: E,
) -> Vec<E> {
    let num_mls = mls.len();
    let num_periodic = periodic_table.num_columns();
    let num_vars = mls[0].num_variables();
    let num_rounds = num_vars - 1;

    #[cfg(not(feature = "concurrent"))]
    let evaluations = {
        let mut evals_one = vec![E::ZERO; num_mls];
        let mut evals_zero = vec![E::ZERO; num_mls];
        let mut evals_x = vec![E::ZERO; num_mls];

        let mut evals_periodic_one = vec![E::ZERO; num_periodic];
        let mut evals_periodic_zero = vec![E::ZERO; num_periodic];
        let mut evals_periodic_x = vec![E::ZERO; num_periodic];

        let mut deltas = vec![E::ZERO; num_mls];
        let mut deltas_periodic = vec![E::ZERO; num_periodic];

        let mut numerators = vec![E::ZERO; evaluator.get_num_fractions()];
        let mut denominators = vec![E::ZERO; evaluator.get_num_fractions()];
        (0..1 << num_rounds)
            .map(|i| {
                let mut poly_evals = vec![E::ZERO; evaluator.max_degree()];

                for (j, ml) in mls.iter().enumerate() {
                    evals_zero[j] = ml.evaluations()[2 * i];
                    evals_one[j] = ml.evaluations()[2 * i + 1];
                }

                // add evaluation of periodic columns
                periodic_table.fill_periodic_values_at(2 * i, &mut evals_periodic_zero);
                periodic_table.fill_periodic_values_at(2 * i + 1, &mut evals_periodic_one);

                // `(0, \cdots, 0, x_{i+1}, \cdots x_{\nu - 1})`
                let j = i << (sum_check_round + 1);
                // `Eq((\alpha_{0}, \cdots, \alpha_{\nu - 1}); (0, \cdots, 0, x_{i+1}, \cdots x_{\nu - 1})) `
                let eq_at_zero = eq_ml.evaluations()[j];

                // compute the evaluation at 0
                evaluator.evaluate_query(
                    &evals_zero,
                    &evals_periodic_zero,
                    log_up_randomness,
                    &mut numerators,
                    &mut denominators,
                );
                poly_evals[0] = evaluate_composition_poly(
                    eq_mu,
                    &numerators,
                    &denominators,
                    eq_at_zero,
                    r_sum_check,
                );

                // compute the evaluations at 2, ..., d_max points
                for i in 0..num_mls {
                    deltas[i] = evals_one[i] - evals_zero[i];
                    evals_x[i] = evals_one[i];
                }
                for i in 0..num_periodic {
                    deltas_periodic[i] = evals_periodic_one[i] - evals_periodic_zero[i];
                    evals_periodic_x[i] = evals_periodic_one[i];
                }

                for e in poly_evals.iter_mut().skip(1) {
                    evals_x.iter_mut().zip(deltas.iter()).for_each(|(evx, delta)| {
                        *evx += *delta;
                    });
                    evals_periodic_x.iter_mut().zip(deltas_periodic.iter()).for_each(
                        |(evx, delta)| {
                            *evx += *delta;
                        },
                    );

                    evaluator.evaluate_query(
                        &evals_x,
                        &evals_periodic_x,
                        log_up_randomness,
                        &mut numerators,
                        &mut denominators,
                    );
                    *e = evaluate_composition_poly(
                        eq_mu,
                        &numerators,
                        &denominators,
                        eq_at_zero,
                        r_sum_check,
                    );
                }

                poly_evals
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
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; evaluator.get_num_fractions()],
                    vec![E::ZERO; evaluator.get_num_fractions()],
                    vec![E::ZERO; num_mls],
                    vec![E::ZERO; num_periodic],
                    vec![E::ZERO; evaluator.max_degree()],
                )
            },
            |(
                mut evals_zero,
                mut evals_one,
                mut evals_x,
                mut evals_periodic_zero,
                mut evals_periodic_one,
                mut evals_periodic_x,
                mut numerators,
                mut denominators,
                mut deltas,
                mut deltas_periodic,
                mut poly_evals,
            ),
             i| {
                for (j, ml) in mls.iter().enumerate() {
                    evals_zero[j] = ml.evaluations()[2 * i];
                    evals_one[j] = ml.evaluations()[2 * i + 1];
                }

                // add evaluation of periodic columns
                periodic_table.fill_periodic_values_at(2 * i, &mut evals_periodic_zero);
                periodic_table.fill_periodic_values_at(2 * i + 1, &mut evals_periodic_one);

                // `(0, \cdots, 0, x_{i+1}, \cdots x_{\nu - 1})`
                let j = i << (sum_check_round + 1);
                // `Eq((\alpha_{0}, \cdots, \alpha_{\nu - 1}); (0, \cdots, 0, x_{i+1}, \cdots x_{\nu - 1})) `
                let eq_at_zero = eq_ml.evaluations()[j];

                // compute the evaluation at 0
                evaluator.evaluate_query(
                    &evals_zero,
                    &evals_periodic_zero,
                    log_up_randomness,
                    &mut numerators,
                    &mut denominators,
                );
                poly_evals[0] += evaluate_composition_poly(
                    eq_mu,
                    &numerators,
                    &denominators,
                    eq_at_zero,
                    r_sum_check,
                );

                // compute the evaluations at 2, ..., d_max points
                for i in 0..num_mls {
                    deltas[i] = evals_one[i] - evals_zero[i];
                    evals_x[i] = evals_one[i];
                }
                for i in 0..num_periodic {
                    deltas_periodic[i] = evals_periodic_one[i] - evals_periodic_zero[i];
                    evals_periodic_x[i] = evals_periodic_one[i];
                }

                for e in poly_evals.iter_mut().skip(1) {
                    evals_x.iter_mut().zip(deltas.iter()).for_each(|(evx, delta)| {
                        *evx += *delta;
                    });
                    evals_periodic_x.iter_mut().zip(deltas_periodic.iter()).for_each(
                        |(evx, delta)| {
                            *evx += *delta;
                        },
                    );

                    evaluator.evaluate_query(
                        &evals_x,
                        &evals_periodic_x,
                        log_up_randomness,
                        &mut numerators,
                        &mut denominators,
                    );
                    *e += evaluate_composition_poly(
                        eq_mu,
                        &numerators,
                        &denominators,
                        eq_at_zero,
                        r_sum_check,
                    );
                }

                (
                    evals_zero,
                    evals_one,
                    evals_x,
                    evals_periodic_zero,
                    evals_periodic_one,
                    evals_periodic_x,
                    numerators,
                    denominators,
                    deltas,
                    deltas_periodic,
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

    evaluations
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
