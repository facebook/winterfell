// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains helper structs and methods to estimate the security of STARK proofs.
//!
//! This module provides security estimation in two regimes:
//! - **Conjectured security**: Based on Conjecture 1 in IACR ePrint 2021/582
//! - **Proven security**: Based on round-by-round soundness analysis from IACR ePrint 2024/1553
//!   with Johnson-regime improvements from IACR ePrint 2025/2055
//!
//! The module also provides grinding schedule planning for achieving target security levels
//! with the help of grinding while optimizing prover work.

// Module declarations
mod conjectured;
mod grinding;
mod proven;

#[cfg(test)]
mod tests;

// Re-exports
pub use conjectured::ConjecturedSecurity;
pub use grinding::{
    find_min_grinding_ldr, find_min_grinding_udr, find_min_queries_ldr, find_min_queries_udr,
    plan_grinding_schedule_ldr, plan_grinding_schedule_udr, summarize_ldr, summarize_udr,
    GrindingSchedule, RoundSecurity, SecuritySummary,
};
pub use proven::ProvenSecurity;

// CONSTANTS
// ================================================================================================

pub(crate) const GRINDING_CONTRIBUTION_FLOOR: u32 = 80;
pub(crate) const MAX_PROXIMITY_PARAMETER: u64 = 1000;

// MATH HELPER FUNCTIONS
// ================================================================================================

#[cfg(feature = "std")]
pub(crate) fn log2(value: f64) -> f64 {
    value.log2()
}

#[cfg(not(feature = "std"))]
pub(crate) fn log2(value: f64) -> f64 {
    libm::log2(value)
}

#[cfg(feature = "std")]
pub(crate) fn sqrt(value: f64) -> f64 {
    value.sqrt()
}

#[cfg(not(feature = "std"))]
pub(crate) fn sqrt(value: f64) -> f64 {
    libm::sqrt(value)
}

#[cfg(feature = "std")]
pub(crate) fn powf(value: f64, exp: f64) -> f64 {
    value.powf(exp)
}

#[cfg(not(feature = "std"))]
pub(crate) fn powf(value: f64, exp: f64) -> f64 {
    libm::pow(value, exp)
}

#[cfg(feature = "std")]
pub(crate) fn ceil(value: f64) -> f64 {
    value.ceil()
}

#[cfg(not(feature = "std"))]
pub(crate) fn ceil(value: f64) -> f64 {
    libm::ceil(value)
}

// BATCHING HELPER
// ================================================================================================

use crate::BatchingMethod;

/// Returns the batching factor for the given batching method and count.
/// For linear batching, factor is 1.0. For algebraic/Horner batching, factor is (count - 1).
pub(crate) fn batching_factor(method: BatchingMethod, count: usize) -> f64 {
    match method {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => count as f64 - 1.0,
    }
}
