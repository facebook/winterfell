// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;
#[cfg(feature = "concurrent")]
pub use rayon::prelude::*;

use super::{compute_scaling_down_factors, to_coefficients, SumCheckProverError};
use crate::{comb_func, FinalOpeningClaim, MultiLinearPoly, RoundProof, SumCheckProof};

/// Sum-check prover for non-linear multivariate polynomial of the simple LogUp-GKR.
///
/// More specifically, the following function implements the logic of the sum-check prover as
/// described in Section 3.2 in [1], that is, given verifier challenges  , the following implements
/// the sum-check prover for the following two statements
/// $$
/// p_{\nu - \kappa}\left(v_{\kappa+1}, \cdots, v_{\nu}\right) = \sum_{w_i}
///     EQ\left(\left(v_{\kappa+1}, \cdots, v_{\nu}\right), \left(w_{\kappa+1}, \cdots,
///                              w_{\nu}\right)\right) \cdot
///      \left( p_{\nu-\kappa+1}\left(1, w_{\kappa+1}, \cdots, w_{\nu}\right)  \cdot
///              q_{\nu-\kappa+1}\left(0, w_{\kappa+1}, \cdots, w_{\nu}\right) +
///     p_{\nu-\kappa+1}\left(0, w_{\kappa+1}, \cdots, w_{\nu}\right)  \cdot
///     q_{\nu-\kappa+1}\left(1, w_{\kappa+1}, \cdots, w_{\nu}\right)\right)
/// $$
///
/// and
///
/// $$
/// q_{\nu -k}\left(v_{\kappa+1}, \cdots, v_{\nu}\right) = \sum_{w_i}EQ\left(\left(v_{\kappa+1},
///  \cdots, v_{\nu}\right), \left(w_{\kappa+1}, \cdots, w_{\nu }\right)\right) \cdot
/// \left( q_{\nu-\kappa+1}\left(1, w_{\kappa+1}, \cdots, w_{\nu}\right)  \cdot
///  q_{\nu-\kappa+1}\left(0, w_{\kappa+1}, \cdots, w_{\nu}\right)\right)
/// $$
///
/// for $k = 1, \cdots, \nu - 1$  
///
/// Instead of executing two runs of the sum-check protocol, a batching randomness `r_batch` is
/// sent by the verifier at the outset in order to batch the two statments.
///
/// Note that the degree of the non-linear composition polynomial is 3.
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
/// means that due to the degrees being off by $1$, the prover uses the linear factor in order to
/// obtain an additional evaluation point in order to be able to interpolate $v_{i+1}(X)$.
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
pub fn sumcheck_prove_plain<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>>(
    mut claim: E,
    gkr_point: &[E],
    r_batch: E,
    p: MultiLinearPoly<E>,
    q: MultiLinearPoly<E>,
    eq: &mut MultiLinearPoly<E>,
    transcript: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
) -> Result<SumCheckProof<E>, SumCheckProverError> {
    let mut round_proofs = vec![];

    let mut challenges = vec![];

    // construct the vector of multi-linear polynomials
    let (mut p0, mut p1) = p.project_least_significant_variable();
    let (mut q0, mut q1) = q.project_least_significant_variable();

    let num_rounds = p0.num_variables();

    let scaling_down_factors = compute_scaling_down_factors(gkr_point);
    let mut scaling_up_factor = E::ONE;

    for i in 0..num_rounds {
        let len = p0.num_evaluations() / 2;

        #[cfg(not(feature = "concurrent"))]
        let (round_poly_eval_at_0, round_poly_eval_at_2) =
            (0..len).fold((E::ZERO, E::ZERO), |(acc_point_0, acc_point_2), k| {
                let j = k << (i + 1);
                let round_poly_eval_at_0 =
                    comb_func(p0[2 * k], p1[2 * k], q0[2 * k], q1[2 * k], eq[j], r_batch);

                let p0_delta = p0[2 * k + 1] - p0[2 * k];
                let p1_delta = p1[2 * k + 1] - p1[2 * k];
                let q0_delta = q0[2 * k + 1] - q0[2 * k];
                let q1_delta = q1[2 * k + 1] - q1[2 * k];

                let p0_eval_at_x = p0[2 * k + 1] + p0_delta;
                let p1_eval_at_x = p1[2 * k + 1] + p1_delta;
                let q0_eval_at_x = q0[2 * k + 1] + q0_delta;
                let q1_eval_at_x = q1[2 * k + 1] + q1_delta;
                let round_poly_eval_at_2 = comb_func(
                    p0_eval_at_x,
                    p1_eval_at_x,
                    q0_eval_at_x,
                    q1_eval_at_x,
                    eq[j],
                    r_batch,
                );

                (round_poly_eval_at_0 + acc_point_0, round_poly_eval_at_2 + acc_point_2)
            });

        #[cfg(feature = "concurrent")]
        let (round_poly_eval_at_0, round_poly_eval_at_2) = (0..len)
            .into_par_iter()
            .fold(
                || (E::ZERO, E::ZERO),
                |(a, b), k| {
                    let j = k << (i + 1);
                    let round_poly_eval_at_0 =
                        comb_func(p0[2 * k], p1[2 * k], q0[2 * k], q1[2 * k], eq[j], r_batch);

                    let p0_delta = p0[2 * k + 1] - p0[2 * k];
                    let p1_delta = p1[2 * k + 1] - p1[2 * k];
                    let q0_delta = q0[2 * k + 1] - q0[2 * k];
                    let q1_delta = q1[2 * k + 1] - q1[2 * k];

                    let p0_eval_at_x = p0[2 * k + 1] + p0_delta;
                    let p1_eval_at_x = p1[2 * k + 1] + p1_delta;
                    let q0_eval_at_x = q0[2 * k + 1] + q0_delta;
                    let q1_eval_at_x = q1[2 * k + 1] + q1_delta;
                    let round_poly_eval_at_2 = comb_func(
                        p0_eval_at_x,
                        p1_eval_at_x,
                        q0_eval_at_x,
                        q1_eval_at_x,
                        eq[j],
                        r_batch,
                    );

                    (round_poly_eval_at_0 + a, round_poly_eval_at_2 + b)
                },
            )
            .reduce(|| (E::ZERO, E::ZERO), |(a0, b0), (a1, b1)| (a0 + a1, b0 + b1));

        let alpha_i = gkr_point[i];
        let compressed_round_poly = to_coefficients(
            &mut [round_poly_eval_at_0, round_poly_eval_at_2],
            claim,
            alpha_i,
            scaling_down_factors[i],
            scaling_up_factor,
        );

        // reseed with the s_i polynomial
        transcript.reseed(H::hash_elements(&compressed_round_poly.0));
        let round_proof = RoundProof {
            round_poly_coefs: compressed_round_poly.clone(),
        };

        let round_challenge =
            transcript.draw().map_err(|_| SumCheckProverError::FailedToGenerateChallenge)?;

        // fold each multi-linear using the round challenge
        p0.bind_least_significant_variable(round_challenge);
        p1.bind_least_significant_variable(round_challenge);
        q0.bind_least_significant_variable(round_challenge);
        q1.bind_least_significant_variable(round_challenge);

        // update the scaling up factor
        scaling_up_factor *=
            round_challenge * alpha_i + (E::ONE - round_challenge) * (E::ONE - alpha_i);

        // compute the new reduced round claim
        claim = compressed_round_poly.evaluate_using_claim(&claim, &round_challenge);

        round_proofs.push(round_proof);
        challenges.push(round_challenge);
    }

    Ok(SumCheckProof {
        openings_claim: FinalOpeningClaim {
            eval_point: challenges,
            openings: vec![p0[0], p1[0], q0[0], q1[0]],
        },
        round_proofs,
    })
}
