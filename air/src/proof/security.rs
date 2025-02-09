// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains helper structs and methods to estimate the security of STARK proofs.

use core::cmp;

use crate::{BatchingMethod, ProofOptions};

// CONSTANTS
// ================================================================================================

const GRINDING_CONTRIBUTION_FLOOR: u32 = 80;
const MAX_PROXIMITY_PARAMETER: u64 = 1000;

// CONJECTURED SECURITY
// ================================================================================================

/// Security estimate (in bits) of the protocol under Conjecture 1 in [1].
///
/// [1]: https://eprint.iacr.org/2021/582
pub struct ConjecturedSecurity(u32);

impl ConjecturedSecurity {
    /// Computes the security level (in bits) of the protocol using Eq. (19) in [1].
    ///
    /// [1]: https://eprint.iacr.org/2021/582
    pub fn compute(
        options: &ProofOptions,
        base_field_bits: u32,
        collision_resistance: u32,
    ) -> Self {
        // compute max security we can get for a given field size
        let field_security = base_field_bits * options.field_extension().degree();

        // compute security we get by executing multiple query rounds
        let security_per_query = options.blowup_factor().ilog2();
        let mut query_security = security_per_query * options.num_queries() as u32;

        // include grinding factor contributions only for proofs adequate security
        if query_security >= GRINDING_CONTRIBUTION_FLOOR {
            query_security += options.grinding_factor();
        }

        Self(cmp::min(cmp::min(field_security, query_security) - 1, collision_resistance))
    }

    /// Returns the conjectured security level (in bits).
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Returns whether or not the conjectured security level is greater than or equal to the the
    /// specified security level in bits.
    pub fn is_at_least(&self, bits: u32) -> bool {
        self.0 >= bits
    }
}

// PROVEN SECURITY
// ================================================================================================

/// Proven security estimate (in bits), in list-decoding and unique decoding regimes, of the
/// protocol.
pub struct ProvenSecurity {
    unique_decoding: u32,
    list_decoding: u32,
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

        // determine the interval to which the which the optimal `m` belongs
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

    // we apply Theorem 2 in https://eprint.iacr.org/2024/1553, which is based on Theorem 8 in
    // https://eprint.iacr.org/2022/1216.pdf and Theorem 5 in https://eprint.iacr.org/2021/582
    // Note that the range of m needs to be restricted in order to ensure that eta, the slackness
    // factor to the distance bound, is greater than 0.
    // Determining the range of m is the responsibility of the calling function.
    let mut epsilons_bits_neg = vec![];

    // list size
    let l = m / (rho - (2.0 * m / lde_domain_size));

    // ALI related soundness error. If algebraic/curve batching is used for batching the constraints
    // then there is a loss of log2(C - 1) where C is the total number of constraints.
    let batching_factor = match options.constraint_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic => num_constraints as f64 - 1.0,
    };
    let epsilon_1_bits_neg = -log2(l) - log2(batching_factor) + extension_field_bits;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP related soundness error. Note that this uses that the denominator |F| - |D ∪ H|
    // can be approximated by |F| for all practical domain sizes. We also use the blow-up factor
    // as an upper bound for the maximal constraint degree.
    let epsilon_2_bits_neg = -log2(
        l * l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)),
    ) + extension_field_bits;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // compute FRI commit-phase (i.e., pre-query) soundness error.
    // This considers only the first term given in eq. 7 in https://eprint.iacr.org/2022/1216.pdf,
    // i.e. (m + 0.5)^7 * n^2 * (N - 1) / (3 * q * rho^1.5) as all other terms are negligible in
    // comparison. N is the number of batched polynomials.
    let batching_factor = match options.deep_poly_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic => num_committed_polys as f64 - 1.0,
    };
    let epsilon_3_bits_neg = extension_field_bits
        - log2(
            (powf(m + 0.5, 7.0) / (3.0 * powf(rho, 1.5)))
                * powf(lde_domain_size, 2.0)
                * batching_factor,
        );
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // epsilon_i for i in [3..(k-1)], where k is number of rounds, are also negligible

    // compute FRI query-phase soundness error
    let epsilon_k_bits_neg = options.grinding_factor() as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    // return the round-by-round (RbR) soundness error
    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// Computes proven security level for the specified proof parameters in the unique-decoding regime.
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
    let batching_factor = match options.constraint_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic => num_constraints as f64 - 1.0,
    };
    let epsilon_1_bits_neg = -log2(batching_factor) + extension_field_bits;
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
    let batching_factor = match options.deep_poly_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic => num_committed_polys as f64 - 1.0,
    };
    let epsilon_3_bits_neg = extension_field_bits - log2(lde_domain_size * batching_factor);
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // epsilon_i for i in [3..(k-1)], where k is number of rounds
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

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the largest proximity parameter m such that eta is greater than 0 in the proof of
/// Theorem 1 in https://eprint.iacr.org/2021/582. See Theorem 2 in https://eprint.iacr.org/2024/1553
/// and its proof for more on this point.
///
/// The bound on m in Theorem 2 in https://eprint.iacr.org/2024/1553 is sufficient but we can use
/// the following to compute a better bound.
fn compute_upper_m(h: usize) -> f64 {
    let h = h as f64;
    let ratio = (h + 2.0) / h;
    let m_max = ceil(1.0 / (2.0 * (sqrt(ratio) - 1.0)));
    assert!(m_max >= h / 2.0, "the bound in the theorem should be tighter");

    // We cap the range to 1000 as the optimal m value will be in the lower range of [m_min, m_max]
    // since increasing m too much will lead to a deterioration in the FRI commit soundness making
    // any benefit gained in the FRI query soundess mute.
    cmp::min(m_max as u64, MAX_PROXIMITY_PARAMETER) as f64
}

#[cfg(feature = "std")]
pub fn log2(value: f64) -> f64 {
    value.log2()
}

#[cfg(not(feature = "std"))]
pub fn log2(value: f64) -> f64 {
    libm::log2(value)
}

#[cfg(feature = "std")]
pub fn sqrt(value: f64) -> f64 {
    value.sqrt()
}

#[cfg(not(feature = "std"))]
pub fn sqrt(value: f64) -> f64 {
    libm::sqrt(value)
}

#[cfg(feature = "std")]
pub fn powf(value: f64, exp: f64) -> f64 {
    value.powf(exp)
}

#[cfg(not(feature = "std"))]
pub fn powf(value: f64, exp: f64) -> f64 {
    libm::pow(value, exp)
}

#[cfg(feature = "std")]
pub fn ceil(value: f64) -> f64 {
    value.ceil()
}

#[cfg(not(feature = "std"))]
pub fn ceil(value: f64) -> f64 {
    libm::ceil(value)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use math::{fields::f64::BaseElement, StarkField};

    use super::ProofOptions;
    use crate::{proof::security::ProvenSecurity, BatchingMethod, FieldExtension};

    #[test]
    fn get_100_bits_security() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 4;
        let num_queries = 119;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 100);
        assert_eq!(list_decoding, 69);

        // increasing the queries does not help the LDR case
        let num_queries = 150;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 69);

        // increasing the extension degree does help and we then need fewer queries by virtue
        // of being in LDR
        let field_extension = FieldExtension::Cubic;
        let num_queries = 81;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 100);
    }

    #[test]
    fn unique_decoding_folding_factor_effect() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 7;
        let grinding_factor = 16;
        let blowup_factor = 8;
        let num_queries = 123;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(8);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 116);

        let fri_folding_factor = 4;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 115);
    }

    #[test]
    fn unique_versus_list_decoding_rate_effect() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 7;
        let grinding_factor = 20;
        let blowup_factor = 2;
        let num_queries = 195;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(8);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 100);

        // when the rate is large, going to a larger extension field in order to make full use of
        // being in the LDR might not always be justified

        // we increase the extension degree
        let field_extension = FieldExtension::Cubic;
        // and we reduce the number of required queries to reach the target level, but this is
        // a relatively small, approximately 16%, reduction
        let num_queries = 163;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 100);

        // reducing the rate further changes things
        let field_extension = FieldExtension::Quadratic;
        let blowup_factor = 4;
        let num_queries = 119;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 100);

        // the improvement is now at approximately 32%
        let field_extension = FieldExtension::Cubic;
        let num_queries = 81;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 100);
    }

    #[test]
    fn get_96_bits_security() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 4;
        let num_queries = 80;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(18);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 99);

        // increasing the blowup factor should increase the bits of security gained per query
        let blowup_factor = 8;
        let num_queries = 53;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 99);
    }

    #[test]
    fn get_128_bits_security() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 85;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(18);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 128);

        // increasing the blowup factor should increase the bits of security gained per query
        let blowup_factor = 16;
        let num_queries = 65;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 128);
    }

    #[test]
    fn extension_degree() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 85;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(18);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 70);

        // increasing the extension degree improves the FRI commit phase soundness error and permits
        // reaching 128 bits security
        let field_extension = FieldExtension::Cubic;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 128);
    }

    #[test]
    fn trace_length() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 80;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        let trace_length = 2_usize.pow(16);

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert!(security_1 < security_2);
    }

    #[test]
    fn num_fri_queries() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 60;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        let num_queries = 80;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert!(security_1 < security_2);
    }

    #[test]
    fn blowup_factor() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        let blowup_factor = 16;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert!(security_1 < security_2);
    }

    #[test]
    fn deep_batching_method_udr() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(16);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_1,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 106);

        // when the FRI batching error is not largest when compared to the other soundness error
        // terms, increasing the number of committed polynomials might not lead to a degradation
        // in the round-by-round soundness of the protocol
        let num_committed_polys = 1 << 2;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 106);

        // but after a certain point, there will be a degradation
        let num_committed_polys = 1 << 5;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 104);

        // and this degradation is on the order of log2(N - 1) where N is the number of
        // committed polynomials
        let num_committed_polys = num_committed_polys << 3;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 101);
    }

    #[test]
    fn deep_batching_method_ldr() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(22);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 126);

        // increasing the number of committed polynomials might lead to a degradation
        // in the round-by-round soundness of the protocol on the order of log2(N - 1) where
        // N is the number of committed polynomials. This happens when the FRI batching error
        // is the largest among all errors
        let num_committed_polys = 1 << 8;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 118);
    }

    #[test]
    fn constraints_batching_method_udr() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(16);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_1,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 108);

        // when the total number of constraints is on the order of the size of the LDE domain size
        // there is no degradation in the soundness error when using algebraic/curve batching
        // to batch constraints
        let num_constraints = trace_length * blowup_factor;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 108);

        // but after a certain point, there will be a degradation
        let num_constraints = (trace_length * blowup_factor) << 2;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 107);

        // and this degradation is on the order of log2(C - 1) where C is the total number of
        // constraints
        let num_constraints = num_constraints << 2;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 105);
    }

    #[test]
    fn constraints_batching_method_ldr() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(22);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 126);

        // when the total number of constraints is on the order of the size of the LDE domain size
        // square there is no degradation in the soundness error when using algebraic/curve batching
        // to batch constraints
        let num_constraints = (trace_length * blowup_factor).pow(2);
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 126);

        // and we have a good margin until we see any degradation in the soundness error
        let num_constraints = num_constraints << 12;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_3,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_3, 125);
    }
}
