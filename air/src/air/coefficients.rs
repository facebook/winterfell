// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use crypto::{RandomCoin, RandomCoinError};
use math::{get_power_series, FieldElement};

// CONSTRAINT COMPOSITION COEFFICIENTS
// ================================================================================================
/// Coefficients used in construction of constraint composition polynomial.
///
/// These coefficients are created by the
/// [Air::get_constraint_composition_coefficients()](crate::Air::get_constraint_composition_coefficients)
/// function. In the interactive version of the protocol, the verifier either draws these
/// coefficients uniformly at random from the extension field of the protocol or draws a single
/// random extension field element $\alpha$ and defines the coefficients as $\alpha_i = \alpha^i$.
/// We call the former way way of generating the alpha-s, and hence of batching the constraints,
/// linear/affine batching while we call the latter algebraic/curve batching.
///
/// There is one coefficient for each constraint so that we can compute a random linear
/// combination of constraints as:
/// $$
/// \sum_{i = 0}^k{\alpha_i \cdot C_i(x)}
/// $$
/// where:
/// * $\alpha_i$ is the coefficient for the $i$th constraint.
/// * $C_i(x)$ is an evaluation of the $i$th constraint at $x$.
///
/// The coefficients are separated into two lists: one for transition constraints and another one
/// for boundary constraints. This separation is done for convenience only.
///
/// Note that the soundness error of the protocol will depend on the batching used when computing
/// the constraint composition polynomial. More precisely, when using algebraic batching there
/// might be a loss of log_2(C - 1) bits of RbR soundness of the protocol, where C is the total
/// number of constraints.
#[derive(Debug, Clone)]
pub struct ConstraintCompositionCoefficients<E: FieldElement> {
    pub transition: Vec<E>,
    pub boundary: Vec<E>,
}

impl<E: FieldElement> ConstraintCompositionCoefficients<E> {
    /// Returns new [ConstraintCompositionCoefficients] constructed by splitting the provided
    /// coefficients into transition and boundary coefficients.
    ///
    /// The first `num_transition_constraints` values in the `coefficients` vector are assigned
    /// to the transition coefficients and the remaining coefficients are assigned to boundary
    /// coefficients.
    fn new(mut coefficients: Vec<E>, num_transition_constraints: usize) -> Self {
        let boundary = coefficients.split_off(num_transition_constraints);
        let transition = coefficients;
        Self { transition, boundary }
    }

    /// Generates the random values used in the construction of the constraint composition
    /// polynomial when linear batching is used.
    pub fn draw_linear(
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
        num_transition_constraints: usize,
        num_boundary_constraints: usize,
    ) -> Result<Self, RandomCoinError> {
        let num_coefficients = num_transition_constraints + num_boundary_constraints;
        let coefficients = draw_linear_coefficients(public_coin, num_coefficients)?;
        Ok(Self::new(coefficients, num_transition_constraints))
    }

    /// Generates the random values used in the construction of the constraint composition
    /// polynomial when algebraic batching is used.
    pub fn draw_algebraic(
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
        num_transition_constraints: usize,
        num_boundary_constraints: usize,
    ) -> Result<Self, RandomCoinError> {
        let num_coefficients = num_transition_constraints + num_boundary_constraints;
        let coefficients = draw_algebraic_coefficients(public_coin, num_coefficients)?;
        Ok(Self::new(coefficients, num_transition_constraints))
    }

    /// Generates the random values used in the construction of the constraint composition
    /// polynomial when Horner-type batching is used.
    pub fn draw_horner(
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
        num_transition_constraints: usize,
        num_boundary_constraints: usize,
    ) -> Result<Self, RandomCoinError> {
        let num_coefficients = num_transition_constraints + num_boundary_constraints;
        let mut coefficients = draw_algebraic_coefficients(public_coin, num_coefficients)?;
        coefficients.reverse();
        Ok(Self::new(coefficients, num_transition_constraints))
    }
}

// DEEP COMPOSITION COEFFICIENTS
// ================================================================================================
/// Coefficients used in construction of DEEP composition polynomial.
///
/// These coefficients are created by the
/// [Air::get_deep_composition_coefficients()](crate::Air::get_deep_composition_coefficients)
/// function. In the interactive version of the protocol, the verifier draws these coefficients
/// uniformly at random from the extension field of the protocol.
///
/// The coefficients are used in computing the DEEP composition polynomial as:
/// $$
/// Y(x) = \sum_{i=0}^k{(
///     \alpha_i \cdot (\frac{T_i(x) - T_i(z)}{x - z} +
///     \frac{T_i(x) - T_i(z \cdot g)}{x - z \cdot g})
/// )} + \sum_{j=0}^m{\beta_j \cdot \frac{H_j(x) - H_j(z)}{x - z}}
/// $$
/// where:
/// * $z$ is an out-of-domain point drawn randomly from the entire field. In the interactive version
///   of the protocol, $z$ is provided by the verifier.
/// * $g$ is the generator of the trace domain. This is the $n$th root of unity where $n$ is the
///   length of the execution trace.
/// * $T_i(x)$ is an evaluation of the $i$th trace polynomial at $x$, and $k$ is the total number of
///   trace polynomials (which is equal to the width of the execution trace).
/// * $H_i(x)$ is an evaluation of the $j$th constraint composition column polynomial at $x$, and
///   $m$ is the total number of column polynomials.
/// * $\alpha_i$ is a composition coefficient for the $i$th trace polynomial.
/// * $\beta_j$ is a composition coefficient for the $j$th constraint column polynomial.
///
/// The soundness of the resulting protocol is given in Theorem 8 in https://eprint.iacr.org/2022/1216
/// and it relies on the following points:
///
///
/// 1. The evaluation proofs for each trace polynomial at $z$ and $g \cdot z$ can be batched using
///    the non-normalized Lagrange kernel over the set $\{z, g \cdot z\}$. This, however, requires
///    that the FRI protocol is run with a larger agreement parameter.
/// 2. The resulting $Y(x)$ do not need to be degree adjusted but the soundness error of the
///    protocol needs to be updated. For most combinations of batching parameters, this leads to a
///    negligible increase in soundness error. The formula for the updated error can be found in
///    Theorem 8 of https://eprint.iacr.org/2022/1216.
/// 3. The error will depend on the batching used in building the DEEP polynomial. More precisely,
///    when using algebraic batching there might be a loss of log_2(k + m - 1) bits of soundness.
#[derive(Debug, Clone)]
pub struct DeepCompositionCoefficients<E: FieldElement> {
    /// Trace polynomial composition coefficients $\alpha_i$.
    pub trace: Vec<E>,
    /// Constraint column polynomial composition coefficients $\beta_j$.
    pub constraints: Vec<E>,
}

impl<E: FieldElement> DeepCompositionCoefficients<E> {
    /// Returns new [DeepCompositionCoefficients] constructed by splitting the provided
    /// coefficients into transition and boundary coefficients.
    ///
    /// The first `trace_width` values in the `coefficients` vector are assigned to the trace
    /// coefficients and the remaining coefficients are assigned to constraint coefficients.
    fn new(mut coefficients: Vec<E>, trace_width: usize) -> Self {
        let constraints = coefficients.split_off(trace_width);
        let trace = coefficients;
        Self { trace, constraints }
    }

    /// Generates the random values used in the construction of the DEEP polynomial when linear
    /// batching is used.
    pub fn draw_linear(
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
        trace_width: usize,
        num_constraint_composition_columns: usize,
    ) -> Result<Self, RandomCoinError> {
        let num_coefficients = trace_width + num_constraint_composition_columns;
        let coefficients = draw_linear_coefficients(public_coin, num_coefficients)?;
        Ok(Self::new(coefficients, trace_width))
    }

    /// Generates the random values used in the construction of the DEEP polynomial when algebraic
    /// batching is used.
    pub fn draw_algebraic(
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
        trace_width: usize,
        num_constraint_composition_columns: usize,
    ) -> Result<Self, RandomCoinError> {
        let num_coefficients = trace_width + num_constraint_composition_columns;
        let coefficients = draw_algebraic_coefficients(public_coin, num_coefficients)?;
        Ok(Self::new(coefficients, trace_width))
    }

    /// Generates the random values used in the construction of the DEEP polynomial when Horner-type
    /// batching is used.
    pub fn draw_horner(
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
        trace_width: usize,
        num_constraint_composition_columns: usize,
    ) -> Result<Self, RandomCoinError> {
        let num_coefficients = trace_width + num_constraint_composition_columns;
        let mut coefficients = draw_algebraic_coefficients(public_coin, num_coefficients)?;
        coefficients.reverse();
        Ok(Self::new(coefficients, trace_width))
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a vector of coefficients built from the provided public coin.
///
/// The returned coefficients are drawn uniformly from the provided coin.
fn draw_linear_coefficients<E: FieldElement>(
    public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
    num_coefficients: usize,
) -> Result<Vec<E>, RandomCoinError> {
    (0..num_coefficients).map(|_| public_coin.draw()).collect()
}

/// Returns a vector of coefficients built from the provided public coin.
///
/// A single random value alpha is drawn from the public coin, and the coefficients are computed as
/// successive powers of this alpha.
fn draw_algebraic_coefficients<E: FieldElement>(
    public_coin: &mut impl RandomCoin<BaseField = E::BaseField>,
    num_coefficients: usize,
) -> Result<Vec<E>, RandomCoinError> {
    let alpha: E = public_coin.draw()?;
    Ok(get_power_series(alpha, num_coefficients))
}
