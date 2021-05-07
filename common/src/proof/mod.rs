// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{FieldExtension, ProofOptions};
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

    pub fn security_level(&self, optimistic: bool) -> u32 {
        let options = &self.context.options;

        // conjectured security requires half the queries as compared to proven security
        let num_queries = if optimistic {
            options.num_queries()
        } else {
            options.num_queries() / 2
        };

        let one_over_rho =
            (options.blowup_factor() / self.context.ce_blowup_factor as usize) as u32;
        let security_per_query = 31 - one_over_rho.leading_zeros(); // same as log2(one_over_rho)
        let mut result = security_per_query * num_queries as u32;

        // include grinding factor contributions only for proofs adequate security
        if result >= GRINDING_CONTRIBUTION_FLOOR {
            result += options.grinding_factor();
        }

        // Provided by the collision resistance (CR) of the hash function we use
        // TODO: make this dynamic based on the hash function used
        let cr_security = 128;

        // determine number of bits in the field modulus
        let field_modulus_bits = get_num_modulus_bits(&self.context.field_modulus_bytes);

        // field_modulus_bits * field_extension_factor - log2(extended trace length)
        let field_extension_factor = match options.field_extension() {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
        };
        let max_fri_security =
            field_modulus_bits * field_extension_factor - self.context.lde_domain_depth as u32;

        std::cmp::min(std::cmp::min(result, max_fri_security), cr_security)
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
