// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Conjectured security estimation based on Conjecture 1 in https://eprint.iacr.org/2021/582

use core::cmp;

use super::GRINDING_CONTRIBUTION_FLOOR;
use crate::ProofOptions;

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
