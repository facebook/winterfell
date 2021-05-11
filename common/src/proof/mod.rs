// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ProofOptions;
use core::cmp;
use fri::FriProof;
use serde::{Deserialize, Serialize};

mod commitments;
pub use commitments::Commitments;

mod queries;
pub use queries::Queries;

mod ood_frame;
pub use ood_frame::OodEvaluationFrame;

// CONSTANTS
// ================================================================================================

const GRINDING_CONTRIBUTION_FLOOR: u32 = 80;

// TYPES AND INTERFACES
// ================================================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof {
    pub context: Context,
    pub commitments: Commitments,
    pub trace_queries: Queries,
    pub constraint_queries: Queries,
    pub ood_frame: OodEvaluationFrame,
    pub fri_proof: FriProof,
    pub pow_nonce: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Context {
    pub lde_domain_depth: u8,
    pub ce_blowup_factor: u8,
    pub field_modulus_bytes: Vec<u8>,
    pub options: ProofOptions,
}

// STARK PROOF IMPLEMENTATION
// ================================================================================================
impl StarkProof {
    /// Returns proof options which were used to generate this proof.
    pub fn options(&self) -> &ProofOptions {
        &self.context.options
    }

    /// Returns trace length for the computation described by this proof.
    pub fn trace_length(&self) -> usize {
        2usize.pow(self.context.lde_domain_depth as u32) / self.context.options.blowup_factor()
    }

    // SECURITY LEVEL
    // --------------------------------------------------------------------------------------------

    /// Returns security level of this proof (in bits). When `conjectured` is true, conjectured
    /// security level is returned; otherwise, proven security level is returned. Usually, the
    /// number of queries needed for proven security is 2x - 3x higher than the number of queries
    /// needed for conjectured security.
    pub fn security_level(&self, conjectured: bool) -> u32 {
        let options = &self.context.options;

        let base_field_size_bits = get_num_modulus_bits(&self.context.field_modulus_bytes);
        let lde_domain_size_bits = self.context.lde_domain_depth as u32;

        let ce_to_lde_blowup = options.blowup_factor() as u8 / self.context.ce_blowup_factor;
        let evaluation_domain_size_bits = lde_domain_size_bits / ce_to_lde_blowup as u32;

        if conjectured {
            get_conjectured_security(
                options,
                base_field_size_bits,
                lde_domain_size_bits,
                evaluation_domain_size_bits,
            )
        } else {
            // TODO: implement proven security estimation
            unimplemented!("proven security estimation has not been implement yet")
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns number of bits in the provided modulus; the modulus is assumed to be encoded in
/// little-endian byte order
fn get_num_modulus_bits(modulus_bytes: &[u8]) -> u32 {
    let mut num_bits = modulus_bytes.len() as u32 * 8;
    for &byte in modulus_bytes.iter().rev() {
        if byte != 0 {
            num_bits -= byte.leading_zeros();
            return num_bits;
        }
        num_bits -= 8;
    }

    0
}

/// Computes conjectured security level for the specified proof parameters.
fn get_conjectured_security(
    options: &ProofOptions,
    base_field_size: u32,        // in bits
    lde_domain_size: u32,        // in bits
    evaluation_domain_size: u32, // in bits
) -> u32 {
    // compute max security we can get for a given field size
    let field_size = base_field_size * options.field_extension().degree();
    let field_security = field_size - lde_domain_size;

    // compute max security we can get for a given hash function
    let hash_fn_security = options.hash_fn().collision_resistance();

    // compute security we get by executing multiple query rounds
    let one_over_rho = lde_domain_size / evaluation_domain_size;
    let security_per_query = one_over_rho.trailing_zeros(); // same as log2(one_over_rho)
    let mut query_security = security_per_query * options.num_queries() as u32;

    // include grinding factor contributions only for proofs adequate security
    if query_security >= GRINDING_CONTRIBUTION_FLOOR {
        query_security += options.grinding_factor();
    }

    cmp::min(cmp::min(field_security, hash_fn_security), query_security) - 1
}
