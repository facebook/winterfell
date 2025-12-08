// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Grinding schedule planning for round-by-round soundness.
//!
//! This module provides functions for planning optimal grinding schedules to achieve target
//! security levels in both list-decoding regime (LDR) and unique-decoding regime (UDR).

use alloc::{fmt, vec::Vec};
use core::fmt::{Display, Formatter};

use super::{batching_factor, log2, powf, proven::compute_upper_m, sqrt};
use crate::ProofOptions;

// GRINDING SCHEDULE
// ================================================================================================
// Represents per-round grinding bits to boost round-by-round soundness, as per the grinding lemma
// in the ethSTARK paper (IACR ePrint 2021/582). Each value adds that many bits to the
// corresponding round's epsilon in the round-by-round soundness vector.
//
// Rounds:
//
//  - ε₁: ALI - randomness used to batch constraints
//  - ε₂: DEEP - randomness for out-of-domain (OOD) challenges
//  - ε₃: FRI batching - randomness to batch multiple polynomials for FRI
//  - ε₄, ..., εₖ₋₁: FRI intermediate layers - one grinding per FRI folding challenge
//  - εₖ: FRI query - randomness for the FRI query seed (TODO: this should override
//    options.grinding_factor.)
//
// Note: With many FRI layers, total grinding cost increases as each intermediate layer must be
// boosted to the target. The optimizer tends to prefer smaller proximity parameter m to strengthen
// commit-phase rounds (ε₁-εₖ₋₁), accepting weaker query soundness (εₖ) which can be compensated
// with grinding at a single location.
#[derive(Clone, Debug, Default)]
pub struct GrindingSchedule {
    pub ali: u32,
    pub deep: u32,
    pub fri_batching: u32,
    /// Grinding for each FRI intermediate layer (ε₄, ..., εₖ₋₁).
    /// Length equals the number of FRI folding layers.
    pub fri_intermediate: Vec<u32>,
    pub fri_query: u32,
}

impl GrindingSchedule {
    /// Returns the total grinding cost as log₂(number of hashes).
    pub fn cost_log2(&self) -> f64 {
        let cost = powf(2.0, self.ali as f64)
            + powf(2.0, self.deep as f64)
            + powf(2.0, self.fri_batching as f64)
            + self.fri_intermediate.iter().map(|&b| powf(2.0, b as f64)).sum::<f64>()
            + powf(2.0, self.fri_query as f64);
        log2(cost)
    }
}

// SECURITY SUMMARY
// ================================================================================================

/// Summary of round-by-round security analysis for a grinding schedule.
///
/// Contains baseline security bits (before grinding), grinding deltas, and final security
/// for each round in the protocol. Implements `Display` for human-readable output.
#[derive(Clone, Debug)]
pub struct SecuritySummary {
    /// Target security level in bits.
    pub target_bits: u32,
    /// Proximity parameter m (only for LDR).
    pub proximity_parameter: Option<u32>,
    /// Baseline security bits per round (before grinding).
    pub baseline: RoundSecurity,
    /// Grinding bits applied per round.
    pub grinding: GrindingSchedule,
    /// Total grinding cost as log₂(number of hashes).
    pub total_grinding_cost_log2: f64,
}

/// Per-round baseline security bits (before grinding).
#[derive(Clone, Debug)]
pub struct RoundSecurity {
    pub ali: f64,
    pub deep: f64,
    pub fri_batching: f64,
    pub fri_intermediate: Vec<f64>,
    pub fri_query: f64,
}

impl Display for SecuritySummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "Security Summary")?;
        writeln!(f, "================")?;
        if let Some(m) = self.proximity_parameter {
            writeln!(f, "Regime: LDR (m={})", m)?;
        } else {
            writeln!(f, "Regime: UDR")?;
        }
        writeln!(f, "Target: {} bits", self.target_bits)?;
        writeln!(f)?;
        writeln!(f, "{:20} {:>12} {:>10} {:>12}", "Round", "Baseline", "Grinding", "Final")?;
        writeln!(f, "{:-<20} {:-<12} {:-<10} {:-<12}", "", "", "", "")?;

        // Helper to format a row
        let row =
            |f: &mut Formatter<'_>, name: &str, baseline: f64, grinding: u32| -> fmt::Result {
                writeln!(
                    f,
                    "{:20} {:>12.2} {:>10} {:>12.2}",
                    name,
                    baseline,
                    grinding,
                    baseline + grinding as f64
                )
            };

        row(f, "ε₁ (ALI)", self.baseline.ali, self.grinding.ali)?;
        row(f, "ε₂ (DEEP)", self.baseline.deep, self.grinding.deep)?;
        row(f, "ε₃ (FRI batching)", self.baseline.fri_batching, self.grinding.fri_batching)?;

        for (i, (&baseline, &grinding)) in self
            .baseline
            .fri_intermediate
            .iter()
            .zip(&self.grinding.fri_intermediate)
            .enumerate()
        {
            let name = fmt::format(format_args!("ε₄₊{} (FRI layer {})", i, i));
            row(f, &name, baseline, grinding)?;
        }

        row(f, "εₖ (Query)", self.baseline.fri_query, self.grinding.fri_query)?;

        writeln!(f)?;
        writeln!(f, "Total grinding cost: 2^{:.2} hashes", self.total_grinding_cost_log2)?;

        Ok(())
    }
}

/// Computes a grinding schedule to reach a target security level in the list-decoding regime.
///
/// For each candidate proximity parameter m, this function computes the baseline security bits
/// for each round without grinding. It then calculates the grinding deltas needed to lift all
/// rounds to the target security level.
///
/// The optimal m is chosen to minimize total expected prover work, measured as the log-sum-exp
/// of the grinding deltas: Σ 2^{delta_i} (in base 2). Ties are broken by L1 norm (Σ delta_i),
/// then by preferring smaller m.
///
/// # Returns
///
/// Returns the grinding schedule and the chosen proximity parameter `m`.
///
/// # Panics
///
/// Panics if `target_bits` exceeds the field size or collision resistance.
pub fn plan_grinding_schedule_ldr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
) -> (GrindingSchedule, u32) {
    let field_cap = base_field_bits * options.field_extension().degree();
    let cap = field_cap.min(collision_resistance);
    assert!(
        target_bits <= cap,
        "target_bits ({target_bits}) exceeds maximum achievable security ({cap})"
    );

    let lde_domain_size = trace_domain_size * options.blowup_factor();
    let num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size);

    // Helper: compute per-round bits (no schedule, query grinding = 0) for a given m
    fn round_bits_for_m(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        m: usize,
        num_constraints: usize,
        num_committed_polys: usize,
        num_fri_layers: usize,
    ) -> (f64, f64, f64, Vec<f64>, f64) {
        let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
        let num_fri_queries = options.num_queries() as f64;
        let m = m as f64;
        let rho = 1.0 / options.blowup_factor() as f64;
        let alpha = (1.0 + 0.5 / m) * sqrt(rho);
        let max_deg = options.blowup_factor() as f64 + 1.0;
        let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
        let trace_domain_size = trace_domain_size as f64;
        let num_openings = 2.0;

        // ALI
        let l = m / (rho - (2.0 * m / lde_domain_size));
        let constraint_batching =
            batching_factor(options.constraint_batching_method(), num_constraints);
        let b1 = -log2(l) - log2(constraint_batching) + extension_field_bits;

        // DEEP
        let b2 = -log2(
            l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)),
        ) + extension_field_bits;

        // FRI batching base (without batching constant)
        // Note: FRI layer errors do NOT depend on the batching constant.
        // They only depend on the folding factor, domain size, and proximity parameter m.
        let b3_no_batching = extension_field_bits
            - log2((2.0 * powf(m + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size);

        // FRI batching with batching constant (only affects ε₃)
        let deep_batching =
            batching_factor(options.deep_poly_batching_method(), num_committed_polys);
        let b3 = b3_no_batching - log2(deep_batching);

        // ε₄, ..., εₖ₋₁: FRI intermediate layers (one per folding step)
        let folding_factor = options.to_fri_options().folding_factor() as f64;
        let mut fri_layer_bits = Vec::with_capacity(num_fri_layers);
        let mut current_domain_size = lde_domain_size;

        for _ in 0..num_fri_layers {
            current_domain_size /= folding_factor;

            // Two contributions to intermediate layer bound
            let term_from_b3 = b3_no_batching; // Use version without batching constant
            let term_from_n_over_q = extension_field_bits
                - log2(folding_factor)
                - log2(current_domain_size + 1.0)
                - log2(2.0 * m + 1.0)
                + 0.5 * log2(rho);

            let b_layer = term_from_b3.min(term_from_n_over_q);
            fri_layer_bits.push(b_layer);
        }

        // εₖ: Query
        let bq = -log2(powf(alpha, num_fri_queries));
        (b1, b2, b3, fri_layer_bits, bq)
    }

    // Search for optimal m by minimizing Σ 2^{delta_i}
    let m_min: usize = 3;
    let m_max = compute_upper_m(trace_domain_size).max(4.0) as usize;
    let mut best_cost_log2 = f64::INFINITY;
    let mut best_l1 = u64::MAX;
    let mut best_m = m_min as u32;
    let mut best_schedule = GrindingSchedule::default();

    for m in m_min..m_max {
        let (b1, b2, b3, fri_layer_bits, bq) = round_bits_for_m(
            options,
            base_field_bits,
            trace_domain_size,
            m,
            num_constraints,
            num_committed_polys,
            num_fri_layers,
        );

        // Compute grinding deltas for all rounds
        let t = target_bits as i64;
        let d1 = (t - b1 as i64).max(0) as u32;
        let d2 = (t - b2 as i64).max(0) as u32;
        let d3 = (t - b3 as i64).max(0) as u32;
        let d_fri_layers: Vec<u32> =
            fri_layer_bits.iter().map(|&bits| (t - bits as i64).max(0) as u32).collect();
        let dq = (t - bq as i64).max(0) as u32;

        // Compute cost with per-layer FRI grinding
        let log2_cost = log2(
            powf(2.0, d1 as f64)
                + powf(2.0, d2 as f64)
                + powf(2.0, d3 as f64)
                + d_fri_layers.iter().map(|&delta| powf(2.0, delta as f64)).sum::<f64>()
                + powf(2.0, dq as f64),
        );

        let l1: u64 = d1 as u64
            + d2 as u64
            + d3 as u64
            + d_fri_layers.iter().map(|&delta| delta as u64).sum::<u64>()
            + dq as u64;

        let better = (log2_cost < best_cost_log2)
            || ((log2_cost - best_cost_log2).abs() < 1e-9 && l1 < best_l1)
            || ((log2_cost - best_cost_log2).abs() < 1e-9 && l1 == best_l1 && best_m > m as u32);

        if better {
            best_cost_log2 = log2_cost;
            best_l1 = l1;
            best_m = m as u32;
            best_schedule = GrindingSchedule {
                ali: d1,
                deep: d2,
                fri_batching: d3,
                fri_intermediate: d_fri_layers.clone(),
                fri_query: dq,
            };
        }
    }

    (best_schedule, best_m)
}

/// Computes a grinding schedule to reach a target security level in the unique-decoding regime.
///
/// This function computes the baseline security bits for each round without grinding, then
/// calculates the grinding deltas needed to lift all rounds to the target security level.
///
/// # Panics
///
/// Panics if `target_bits` exceeds the field size or collision resistance.
pub fn plan_grinding_schedule_udr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
) -> GrindingSchedule {
    let field_cap = base_field_bits * options.field_extension().degree();
    let cap = field_cap.min(collision_resistance);
    assert!(
        target_bits <= cap,
        "target_bits ({target_bits}) exceeds maximum achievable security ({cap})"
    );

    let lde_domain_size = trace_domain_size * options.blowup_factor();
    let num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size);

    // Helper: compute per-round bits (no schedule, query grinding = 0)
    fn round_bits(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        num_constraints: usize,
        num_committed_polys: usize,
        num_fri_layers: usize,
    ) -> (f64, f64, f64, Vec<f64>, f64) {
        let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
        let num_fri_queries = options.num_queries() as f64;
        let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
        let trace_domain_size = trace_domain_size as f64;
        let num_openings = 2.0;
        let rho_plus = (trace_domain_size + num_openings) / lde_domain_size;
        let alpha = (1.0 + rho_plus) * 0.5;
        let max_deg = options.blowup_factor() as f64 + 1.0;

        // ALI
        let constraint_batching =
            batching_factor(options.constraint_batching_method(), num_constraints);
        let b1 = -log2(constraint_batching) + extension_field_bits;

        // DEEP
        let b2 =
            -log2(max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0))
                + extension_field_bits;

        // FRI batching (UDR commit-like)
        let deep_batching =
            batching_factor(options.deep_poly_batching_method(), num_committed_polys);
        let b3 = extension_field_bits - log2(lde_domain_size * deep_batching);

        // FRI intermediate layers (UDR analogue)
        let folding_factor = options.to_fri_options().folding_factor() as f64;
        let mut fri_layer_bits = Vec::with_capacity(num_fri_layers);
        let mut current_domain_size = lde_domain_size;

        for _ in 0..num_fri_layers {
            current_domain_size /= folding_factor;
            let b_layer =
                extension_field_bits - log2((folding_factor - 1.0) * (current_domain_size + 1.0));
            fri_layer_bits.push(b_layer);
        }

        // Query
        let bq = -log2(powf(alpha, num_fri_queries));
        (b1, b2, b3, fri_layer_bits, bq)
    }

    let (b1, b2, b3, fri_layer_bits, bq) = round_bits(
        options,
        base_field_bits,
        trace_domain_size,
        num_constraints,
        num_committed_polys,
        num_fri_layers,
    );

    let t = target_bits as i64;
    let d1 = (t - b1 as i64).max(0) as u32;
    let d2 = (t - b2 as i64).max(0) as u32;
    let d3 = (t - b3 as i64).max(0) as u32;
    let d_fri_layers: Vec<u32> =
        fri_layer_bits.iter().map(|&bits| (t - bits as i64).max(0) as u32).collect();
    let dq = (t - bq as i64).max(0) as u32;

    GrindingSchedule {
        ali: d1,
        deep: d2,
        fri_batching: d3,
        fri_intermediate: d_fri_layers,
        fri_query: dq,
    }
}

/// Creates a security summary for a grinding schedule in the list-decoding regime.
///
/// This recomputes the baseline security bits for the given proximity parameter `m`
/// and combines them with the grinding schedule to produce a complete summary.
#[allow(clippy::too_many_arguments)]
pub fn summarize_ldr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
    schedule: &GrindingSchedule,
    m: u32,
) -> SecuritySummary {
    let lde_domain_size = trace_domain_size * options.blowup_factor();
    let num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size);

    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let m_f64 = m as f64;
    let rho = 1.0 / options.blowup_factor() as f64;
    let alpha = (1.0 + 0.5 / m_f64) * sqrt(rho);
    let max_deg = options.blowup_factor() as f64 + 1.0;
    let lde_domain_size_f64 = lde_domain_size as f64;
    let trace_domain_size_f64 = trace_domain_size as f64;
    let num_openings = 2.0;

    // ALI
    let l = m_f64 / (rho - (2.0 * m_f64 / lde_domain_size_f64));
    let constraint_batching =
        batching_factor(options.constraint_batching_method(), num_constraints);
    let b1 = -log2(l) - log2(constraint_batching) + extension_field_bits;

    // DEEP
    let b2 = -log2(
        l * (max_deg * (trace_domain_size_f64 + num_openings - 1.0)
            + (trace_domain_size_f64 - 1.0)),
    ) + extension_field_bits;

    // FRI batching
    let b3_no_batching = extension_field_bits
        - log2((2.0 * powf(m_f64 + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size_f64);
    let deep_batching = batching_factor(options.deep_poly_batching_method(), num_committed_polys);
    let b3 = b3_no_batching - log2(deep_batching);

    // FRI intermediate layers
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let mut fri_layer_bits = Vec::with_capacity(num_fri_layers);
    let mut current_domain_size = lde_domain_size_f64;

    for _ in 0..num_fri_layers {
        current_domain_size /= folding_factor;
        let term_from_b3 = b3_no_batching;
        let term_from_n_over_q = extension_field_bits
            - log2(folding_factor)
            - log2(current_domain_size + 1.0)
            - log2(2.0 * m_f64 + 1.0)
            + 0.5 * log2(rho);
        fri_layer_bits.push(term_from_b3.min(term_from_n_over_q));
    }

    // Query
    let bq = -log2(powf(alpha, num_fri_queries));

    SecuritySummary {
        target_bits,
        proximity_parameter: Some(m),
        baseline: RoundSecurity {
            ali: b1,
            deep: b2,
            fri_batching: b3,
            fri_intermediate: fri_layer_bits,
            fri_query: bq,
        },
        grinding: schedule.clone(),
        total_grinding_cost_log2: schedule.cost_log2(),
    }
}

/// Creates a security summary for a grinding schedule in the unique-decoding regime.
pub fn summarize_udr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
    schedule: &GrindingSchedule,
) -> SecuritySummary {
    let lde_domain_size = trace_domain_size * options.blowup_factor();
    let num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size);

    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let lde_domain_size_f64 = lde_domain_size as f64;
    let trace_domain_size_f64 = trace_domain_size as f64;
    let num_openings = 2.0;
    let rho_plus = (trace_domain_size_f64 + num_openings) / lde_domain_size_f64;
    let alpha = (1.0 + rho_plus) * 0.5;
    let max_deg = options.blowup_factor() as f64 + 1.0;

    // ALI
    let constraint_batching =
        batching_factor(options.constraint_batching_method(), num_constraints);
    let b1 = -log2(constraint_batching) + extension_field_bits;

    // DEEP
    let b2 = -log2(
        max_deg * (trace_domain_size_f64 + num_openings - 1.0) + (trace_domain_size_f64 - 1.0),
    ) + extension_field_bits;

    // FRI batching
    let deep_batching = batching_factor(options.deep_poly_batching_method(), num_committed_polys);
    let b3 = extension_field_bits - log2(lde_domain_size_f64 * deep_batching);

    // FRI intermediate layers
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let mut fri_layer_bits = Vec::with_capacity(num_fri_layers);
    let mut current_domain_size = lde_domain_size_f64;

    for _ in 0..num_fri_layers {
        current_domain_size /= folding_factor;
        fri_layer_bits.push(
            extension_field_bits - log2((folding_factor - 1.0) * (current_domain_size + 1.0)),
        );
    }

    // Query
    let bq = -log2(powf(alpha, num_fri_queries));

    SecuritySummary {
        target_bits,
        proximity_parameter: None,
        baseline: RoundSecurity {
            ali: b1,
            deep: b2,
            fri_batching: b3,
            fri_intermediate: fri_layer_bits,
            fri_query: bq,
        },
        grinding: schedule.clone(),
        total_grinding_cost_log2: schedule.cost_log2(),
    }
}

// QUERY/GRINDING TRADE-OFF HELPERS
// ================================================================================================

/// Finds the minimum number of queries needed to achieve a target security level
/// with at most `max_grinding_log2` bits of grinding work in LDR.
///
/// Returns `None` if no valid configuration exists within the search bounds.
///
/// # Arguments
/// * `base_options` - Base proof options (num_queries will be varied)
/// * `max_grinding_log2` - Maximum allowed grinding cost as log₂(hashes)
/// * `target_bits` - Target security level in bits
///
/// # Example
/// ```ignore
/// // Find minimum queries for 100-bit security with at most 2^20 grinding work
/// let min_queries = find_min_queries_ldr(&options, ..., 20.0, 100);
/// ```
#[allow(clippy::too_many_arguments)]
pub fn find_min_queries_ldr(
    base_options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    max_grinding_log2: f64,
    target_bits: u32,
) -> Option<usize> {
    // Binary search for minimum queries
    let mut lo = 1usize;
    let mut hi = 255usize; // max queries is u8
    let mut result = None;

    while lo <= hi {
        let mid = (lo + hi) / 2;

        let options = ProofOptions::new(
            mid,
            base_options.blowup_factor(),
            0,
            base_options.field_extension(),
            base_options.to_fri_options().folding_factor(),
            base_options.to_fri_options().remainder_max_degree(),
            base_options.constraint_batching_method(),
            base_options.deep_poly_batching_method(),
        );

        // Try to plan a grinding schedule
        let plan_result = std::panic::catch_unwind(|| {
            plan_grinding_schedule_ldr(
                &options,
                base_field_bits,
                trace_domain_size,
                collision_resistance,
                num_constraints,
                num_committed_polys,
                target_bits,
            )
        });

        match plan_result {
            Ok((schedule, _m)) if schedule.cost_log2() <= max_grinding_log2 => {
                result = Some(mid);
                hi = mid - 1;
            },
            _ => {
                lo = mid + 1;
            },
        }
    }

    result
}

/// Finds the minimum grinding cost (as log₂ hashes) to achieve a target security level
/// with the given number of queries in LDR.
///
/// Returns `None` if the target cannot be achieved (exceeds collision resistance).
#[allow(clippy::too_many_arguments)]
pub fn find_min_grinding_ldr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
) -> Option<f64> {
    let result = std::panic::catch_unwind(|| {
        plan_grinding_schedule_ldr(
            options,
            base_field_bits,
            trace_domain_size,
            collision_resistance,
            num_constraints,
            num_committed_polys,
            target_bits,
        )
    });

    result.ok().map(|(schedule, _m)| schedule.cost_log2())
}

/// Finds the minimum number of queries needed to achieve a target security level
/// with at most `max_grinding_log2` bits of grinding work in UDR.
///
/// Returns `None` if no valid configuration exists within the search bounds.
#[allow(clippy::too_many_arguments)]
pub fn find_min_queries_udr(
    base_options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    max_grinding_log2: f64,
    target_bits: u32,
) -> Option<usize> {
    let mut lo = 1usize;
    let mut hi = 255usize;
    let mut result = None;

    while lo <= hi {
        let mid = (lo + hi) / 2;

        let options = ProofOptions::new(
            mid,
            base_options.blowup_factor(),
            0,
            base_options.field_extension(),
            base_options.to_fri_options().folding_factor(),
            base_options.to_fri_options().remainder_max_degree(),
            base_options.constraint_batching_method(),
            base_options.deep_poly_batching_method(),
        );

        let plan_result = std::panic::catch_unwind(|| {
            plan_grinding_schedule_udr(
                &options,
                base_field_bits,
                trace_domain_size,
                collision_resistance,
                num_constraints,
                num_committed_polys,
                target_bits,
            )
        });

        match plan_result {
            Ok(schedule) if schedule.cost_log2() <= max_grinding_log2 => {
                result = Some(mid);
                hi = mid - 1;
            },
            _ => {
                lo = mid + 1;
            },
        }
    }

    result
}

/// Finds the minimum grinding cost (as log₂ hashes) to achieve a target security level
/// with the given number of queries in UDR.
///
/// Returns `None` if the target cannot be achieved (exceeds collision resistance).
#[allow(clippy::too_many_arguments)]
pub fn find_min_grinding_udr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
) -> Option<f64> {
    let result = std::panic::catch_unwind(|| {
        plan_grinding_schedule_udr(
            options,
            base_field_bits,
            trace_domain_size,
            collision_resistance,
            num_constraints,
            num_committed_polys,
            target_bits,
        )
    });

    result.ok().map(|schedule| schedule.cost_log2())
}
