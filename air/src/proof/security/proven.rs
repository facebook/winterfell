// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Proven security estimation based on round-by-round soundness analysis.
//!
//! This module provides security estimates in both the list-decoding regime (LDR) and
//! unique-decoding regime (UDR), following the analysis in IACR ePrint 2024/1553 and
//! incorporating Johnson-regime proximity-gap improvements from IACR ePrint 2025/2055.

use alloc::vec;
use core::cmp;

use super::{batching_factor, ceil, log2, powf, sqrt, GrindingSchedule, MAX_PROXIMITY_PARAMETER};
use crate::ProofOptions;

/// Proven security estimate (in bits), in list-decoding and unique decoding regimes, of the
/// protocol.
pub struct ProvenSecurity {
    pub(crate) unique_decoding: u32,
    pub(crate) list_decoding: u32,
}

impl ProvenSecurity {
    /// Computes the proven security level (in bits) of the protocol using Theorem 2 and Theorem 3
    /// in [1].
    ///
    /// [1]: https://eprint.iacr.org/2024/1553
    pub fn compute(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        collision_resistance: u32,
        num_constraints: usize,
        num_committed_polys: usize,
    ) -> Self {
        let unique_decoding = cmp::min(
            proven_security_protocol_unique_decoding(
                options,
                base_field_bits,
                trace_domain_size,
                num_constraints,
                num_committed_polys,
            ),
            collision_resistance as u64,
        ) as u32;

        // determine the interval to which the optimal `m` belongs
        let m_min: usize = 3;
        let m_max = compute_upper_m(trace_domain_size);

        // search for optimal `m` i.e., the one at which we maximize the number of security bits
        let m_optimal = (m_min as u32..m_max as u32)
        .max_by_key(|&a| {
            proven_security_protocol_for_given_proximity_parameter(
                options,
                base_field_bits,
                trace_domain_size,
                a as usize,
                num_constraints,
                num_committed_polys,
            )
        })
        .expect(
            "Should not fail since m_max is larger than m_min for all trace sizes of length greater than 4",
        );

        let list_decoding = cmp::min(
            proven_security_protocol_for_given_proximity_parameter(
                options,
                base_field_bits,
                trace_domain_size,
                m_optimal as usize,
                num_constraints,
                num_committed_polys,
            ),
            collision_resistance as u64,
        ) as u32;

        Self { unique_decoding, list_decoding }
    }

    /// Computes the proven security level (in bits) using a per-round grinding schedule.
    ///
    /// # Note
    ///
    /// TODO: `schedule.fri_query` overrides `options.grinding_factor` to avoid double-counting
    /// grinding contributions, should be simplified once we remove options.grinding_factor.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_with_schedule(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        collision_resistance: u32,
        num_constraints: usize,
        num_committed_polys: usize,
        schedule: &GrindingSchedule,
    ) -> Self {
        let unique_decoding = cmp::min(
            proven_security_protocol_unique_decoding_with_schedule(
                options,
                base_field_bits,
                trace_domain_size,
                num_constraints,
                num_committed_polys,
                schedule,
            ),
            collision_resistance as u64,
        ) as u32;

        // determine the interval to which the optimal `m` belongs
        let m_min: usize = 3;
        let m_max = compute_upper_m(trace_domain_size);

        // search for optimal `m`
        let m_optimal = (m_min as u32..m_max as u32)
            .max_by_key(|&a| {
                proven_security_protocol_for_given_proximity_parameter_with_schedule(
                    options,
                    base_field_bits,
                    trace_domain_size,
                    a as usize,
                    num_constraints,
                    num_committed_polys,
                    schedule,
                )
            })
            .expect("m_max > m_min for valid trace sizes");

        let list_decoding = cmp::min(
            proven_security_protocol_for_given_proximity_parameter_with_schedule(
                options,
                base_field_bits,
                trace_domain_size,
                m_optimal as usize,
                num_constraints,
                num_committed_polys,
                schedule,
            ),
            collision_resistance as u64,
        ) as u32;

        Self { unique_decoding, list_decoding }
    }

    /// Returns the proven security level (in bits) in the list decoding regime.
    pub fn ldr_bits(&self) -> u32 {
        self.list_decoding
    }

    /// Returns the proven security level (in bits) in the unique decoding regime.
    pub fn udr_bits(&self) -> u32 {
        self.unique_decoding
    }

    /// Returns whether or not the proven security level is greater than or equal to the the
    /// specified security level in bits.
    pub fn is_at_least(&self, bits: u32) -> bool {
        self.list_decoding >= bits || self.unique_decoding >= bits
    }
}

/// Computes proven security level for the specified proof parameters for a fixed value of the
/// proximity parameter m in the list-decoding regime.
fn proven_security_protocol_for_given_proximity_parameter(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    m: usize,
    num_constraints: usize,
    num_committed_polys: usize,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let m = m as f64;
    let rho = 1.0 / options.blowup_factor() as f64;
    let alpha = (1.0 + 0.5 / m) * sqrt(rho);
    // we use the blowup factor in order to bound the max degree
    let max_deg = options.blowup_factor() as f64 + 1.0;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;

    // We follow the round-by-round (RbR) composition from prior analyses and incorporate
    // the Johnson-regime proximity-gap improvements:
    // - For ALI/DEEP and query-phase we keep the structure as in prior work (e.g., 2024/1553 and
    //   2022/1216),
    // - For the FRI commit-phase in LDR we use the improved Johnson-regime bound from IACR ePrint
    //   2025/2055 (Theorem 4.2) which tightens the dominant term and reduces the scaling in n.
    // Note: the range of m must ensure a positive slackness (η > 0 / valid Johnson gap τ > 0);
    // the caller (search over m) is responsible for selecting admissible values.
    let mut epsilons_bits_neg = vec![];

    // list size
    let l = m / (rho - (2.0 * m / lde_domain_size));

    // ALI related soundness error. If algebraic/curve batching is used for batching the constraints
    // then there is a loss of log2(C - 1) where C is the total number of constraints.
    let constraint_batching =
        batching_factor(options.constraint_batching_method(), num_constraints);
    let epsilon_1_bits_neg = -log2(l) - log2(constraint_batching) + extension_field_bits;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP related soundness error. Note that this uses that the denominator |F| - |D ∪ H|
    // can be approximated by |F| for all practical domain sizes. We also use the blow-up factor
    // as an upper bound for the maximal constraint degree.
    let epsilon_2_bits_neg =
        -log2(l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)))
            + extension_field_bits;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // compute FRI commit-phase (i.e., pre-query) soundness error.
    // Johnson-regime improvement (IACR ePrint 2025/2055): dominant term scales as
    //   2 * (m + 1/2)^5 / (3 * ρ^{3/2}) * n * (N - 1),
    // replacing the older (m + 1/2)^7 * n^2 /(3 * ρ^{3/2}) dependence. Here n is the LDE domain size,
    // and N is the number of batched polynomials (captured by deep_batching below).
    let deep_batching = batching_factor(options.deep_poly_batching_method(), num_committed_polys);
    // LDR commit-phase improvement (per IACR ePrint 2025/2055 proximity-gap results):
    // - Replace n^2 with n in the pre-query term (O(n) “exceptions” instead of O(n^2)) in LDR
    //   (e.g., Theorem 4.2 in IACR ePrint 2025/2055).
    // - Replace (m + 0.5)^7 with (m + 0.5)^5 (dominant term exponent tightened by the refined analysis).
    // Johnson-gap parameterization (Theorem 4.2 in IACR ePrint 2025/2055 and Theorem 5.1 in IACR ePrint 2020/654):
    //   Let J(δ) = 1 - sqrt(ρ) and τ = J(δ) - γ. Then
    //     m = max( sqrt(ρ) / (2 * τ), 3 ).
    // Our estimator searches over m directly, so it captures this regime without explicitly computing γ.
    // Lower-order term (∝ (m + 0.5) * γ * ρ) is omitted since its effect is negligible:
    // using γ ≤ J(δ) = 1 - sqrt(ρ), the ratio of lower-order to dominant term satisfies
    //   R ≤ (3/2) * (J(δ) * ρ) / (m + 0.5)^4 = (3/2) * (ρ * (1 - sqrt(ρ))) / (m + 0.5)^4.
    // Numerical example (conservative): m = 3 ⇒ m + 0.5 = 3.5, ρ = 1/2 ⇒ J(δ) ≈ 0.2929.
    // Then R ≤ ~0.00146 ⇒ Δ_bits = log2(1 + R) ≈ 0.002 bits. For larger m or smaller ρ this only decreases.

    // FRI batching base (without batching constant)
    // This is used for FRI layer computations. We denote this as ε₃′ (epsilon_3_no_batching).
    let epsilon_3_no_batching = extension_field_bits
        - log2((2.0 * powf(m + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size);

    // FRI batching with batching constant: -log₂(ε₃) = -log₂(ε₃′) - log₂(deep_batching)
    // (only the ε₃ round is affected by batching)
    let epsilon_3_bits_neg = epsilon_3_no_batching - log2(deep_batching);
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // ε_i for i ∈ [4..(k-1)] (intermediate FRI layers). Using Theorem 5 of IACR ePrint
    // 2021/582 and Theorem 4.2 in IACR ePrint 2025/2055. Noting that t_ℓ are the FRI
    // folding factors, we include for layer j ≥ 0 a contribution of the form
    //   ε_i ≈ ε₃′ · (∏_{r=0}^{i-1} 1/t_r)  and an additive term ~ (n/q).
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    // With fixed folding factor across layers, intermediate errors decrease with layer index.
    // Thus, we bound the entire intermediate range by the first intermediate round (i = 4):
    //   from ε₃′ path:            -log₂(ε₃′) where ε₃′ is ε₃ WITHOUT batching constant
    //   from (n/q) path:          |𝔽| - log₂(t_ℓ) - log₂(n_ℓ + 1) - log₂(2m + 1) + ½log₂(ρ)
    let term_from_e3 = epsilon_3_no_batching;
    let term_from_n_over_q = extension_field_bits
        - log2(folding_factor)
        - log2(lde_domain_size + 1.0)
        - log2(2.0 * m + 1.0)
        + 0.5 * log2(rho);
    let epsilon_i_min_bits_neg = term_from_e3.min(term_from_n_over_q);
    epsilons_bits_neg.push(epsilon_i_min_bits_neg);

    // compute FRI query-phase soundness error
    let epsilon_k_bits_neg = options.grinding_factor() as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    // return the round-by-round (RbR) soundness error
    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// Computes proven security level in the list-decoding regime for a fixed proximity parameter m,
/// using a per-round grinding schedule.
#[allow(clippy::too_many_arguments)]
fn proven_security_protocol_for_given_proximity_parameter_with_schedule(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    m: usize,
    num_constraints: usize,
    num_committed_polys: usize,
    schedule: &GrindingSchedule,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let m = m as f64;
    let rho = 1.0 / options.blowup_factor() as f64;
    let alpha = (1.0 + 0.5 / m) * sqrt(rho);
    let max_deg = options.blowup_factor() as f64 + 1.0;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;

    let mut epsilons_bits_neg = vec![];

    // ALI
    let l = m / (rho - (2.0 * m / lde_domain_size));
    let constraint_batching =
        batching_factor(options.constraint_batching_method(), num_constraints);
    let mut epsilon_1_bits_neg = -log2(l) - log2(constraint_batching) + extension_field_bits;
    epsilon_1_bits_neg += schedule.ali as f64;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP
    let mut epsilon_2_bits_neg =
        -log2(l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)))
            + extension_field_bits;
    epsilon_2_bits_neg += schedule.deep as f64;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // FRI batching base (without batching constant)
    // FRI layers should NOT be affected by the batching constant
    let epsilon_3_no_batching = extension_field_bits
        - log2((2.0 * powf(m + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size);

    // FRI batching with batching constant (only affects ε₃)
    let deep_batching = batching_factor(options.deep_poly_batching_method(), num_committed_polys);
    let mut epsilon_3_bits_neg = epsilon_3_no_batching - log2(deep_batching);
    epsilon_3_bits_neg += schedule.fri_batching as f64;
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // FRI intermediate layers (ε₄, ..., εₖ₋₁)
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let mut current_domain_size = lde_domain_size;

    for &layer_grinding in &schedule.fri_intermediate {
        current_domain_size /= folding_factor;

        let mut epsilon_layer_bits_neg = extension_field_bits
            .min(
                // from ε3 WITHOUT batching constant (batching only affects ε3, not layers)
                epsilon_3_no_batching,
            )
            .min(
                // additive path with constant C = (2m+1)/sqrt(ρ)
                extension_field_bits
                    - log2(folding_factor)
                    - log2(current_domain_size + 1.0)
                    - log2(2.0 * m + 1.0)
                    + 0.5 * log2(rho),
            );
        epsilon_layer_bits_neg += layer_grinding as f64;
        epsilons_bits_neg.push(epsilon_layer_bits_neg);
    }

    // FRI query (override options.grinding_factor)
    let epsilon_k_bits_neg = schedule.fri_query as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// Computes proven security level in the unique-decoding regime using Theorem 3 in
/// https://eprint.iacr.org/2024/1553.
fn proven_security_protocol_unique_decoding(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    num_constraints: usize,
    num_committed_polys: usize,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;
    let rho_plus = (trace_domain_size + num_openings) / lde_domain_size;
    let alpha = (1.0 + rho_plus) * 0.5;
    // we use the blowup factor in order to bound the max degree
    let max_deg = options.blowup_factor() as f64 + 1.0;

    // we apply Theorem 3 in https://eprint.iacr.org/2024/1553
    let mut epsilons_bits_neg = vec![];

    // ALI related soundness error. If algebraic/curve batching is used for batching the constraints
    // then there is a loss of log2(C - 1) where C is the total number of constraints.
    let constraint_batching =
        batching_factor(options.constraint_batching_method(), num_constraints);
    let epsilon_1_bits_neg = -log2(constraint_batching) + extension_field_bits;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP related soundness error. Note that this uses that the denominator |F| - |D ∪ H|
    // can be approximated by |F| for all practical domain sizes. We also use the blow-up factor
    // as an upper bound for the maximal constraint degree
    let epsilon_2_bits_neg =
        -log2(max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0))
            + extension_field_bits;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // compute FRI commit-phase (i.e., pre-query) soundness error. Note that there is no soundness
    // degradation in the case of linear batching while there is a degradation in the order
    // of log2(N - 1) in the case of algebraic batching, where N is the number of polynomials
    // being batched.
    let deep_batching = batching_factor(options.deep_poly_batching_method(), num_committed_polys);
    let epsilon_3_bits_neg = extension_field_bits - log2(lde_domain_size * deep_batching);
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // ε_i for i ∈ [4..(k-1)] (intermediate FRI layers)
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size as usize);
    let epsilon_i_min_bits_neg = (0..num_fri_layers)
        .map(|_| extension_field_bits - log2((folding_factor - 1.0) * (lde_domain_size + 1.0)))
        .fold(f64::INFINITY, |a, b| a.min(b));
    epsilons_bits_neg.push(epsilon_i_min_bits_neg);

    // compute FRI query-phase soundness error
    let epsilon_k_bits_neg = options.grinding_factor() as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    // return the round-by-round (RbR) soundness error
    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// Computes proven security level in the unique-decoding regime using a per-round grinding
/// schedule.
#[allow(clippy::too_many_arguments)]
fn proven_security_protocol_unique_decoding_with_schedule(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    num_constraints: usize,
    num_committed_polys: usize,
    schedule: &GrindingSchedule,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;
    let rho_plus = (trace_domain_size + num_openings) / lde_domain_size;
    let alpha = (1.0 + rho_plus) * 0.5;
    let max_deg = options.blowup_factor() as f64 + 1.0;

    let mut epsilons_bits_neg = vec![];

    // ALI
    let constraint_batching =
        batching_factor(options.constraint_batching_method(), num_constraints);
    let mut epsilon_1_bits_neg = -log2(constraint_batching) + extension_field_bits;
    epsilon_1_bits_neg += schedule.ali as f64;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP
    let mut epsilon_2_bits_neg =
        -log2(max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0))
            + extension_field_bits;
    epsilon_2_bits_neg += schedule.deep as f64;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // FRI batching (commit-like term in UDR)
    let deep_batching = batching_factor(options.deep_poly_batching_method(), num_committed_polys);
    let mut epsilon_3_bits_neg = extension_field_bits - log2(lde_domain_size * deep_batching);
    epsilon_3_bits_neg += schedule.fri_batching as f64;
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // FRI intermediate layers (UDR analogue)
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let mut current_domain_size = lde_domain_size;

    for &layer_grinding in &schedule.fri_intermediate {
        current_domain_size /= folding_factor;
        let epsilon_i_min_bits_neg =
            extension_field_bits - log2((folding_factor - 1.0) * (current_domain_size + 1.0));
        let mut epsilon_layer_bits_neg = epsilon_i_min_bits_neg;
        epsilon_layer_bits_neg += layer_grinding as f64;
        epsilons_bits_neg.push(epsilon_layer_bits_neg);
    }

    // Query phase (override options.grinding_factor)
    let epsilon_k_bits_neg = schedule.fri_query as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// Computes the largest proximity parameter m such that eta is greater than 0 in the proof of
/// Theorem 1 in https://eprint.iacr.org/2021/582. See Theorem 2 in https://eprint.iacr.org/2024/1553
/// and its proof for more on this point.
///
/// The bound on m in Theorem 2 in https://eprint.iacr.org/2024/1553 is sufficient but we can use
/// the following to compute a better bound.
pub(super) fn compute_upper_m(h: usize) -> f64 {
    let h = h as f64;
    let ratio = (h + 2.0) / h;
    let m_max = ceil(1.0 / (2.0 * (sqrt(ratio) - 1.0)));
    assert!(m_max >= h / 2.0, "the bound in the theorem should be tighter");

    // We cap the range to 1000 as the optimal m value will be in the lower range of [m_min, m_max]
    // since increasing m too much will lead to a deterioration in the FRI commit soundness making
    // any benefit gained in the FRI query soundness moot.
    cmp::min(m_max as u64, MAX_PROXIMITY_PARAMETER) as f64
}
