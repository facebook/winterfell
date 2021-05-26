// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ProofOptions;
use math::{field::StarkField, utils::log2};
use serde::{Deserialize, Serialize};

// PROOF HEADER
// ================================================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct Context {
    lde_domain_depth: u8,
    field_modulus_bytes: Vec<u8>,
    options: ProofOptions,
}

impl Context {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new context for a computation described by the specified field, domain, and
    /// proof options.
    pub fn new<B: StarkField>(lde_domain_size: usize, options: ProofOptions) -> Self {
        assert!(
            lde_domain_size.is_power_of_two(),
            "LDE domain size must be a power of two, but was {}",
            lde_domain_size
        );
        Context {
            lde_domain_depth: log2(lde_domain_size) as u8,
            field_modulus_bytes: B::get_modulus_le_bytes(),
            options,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the size of the LDE domain for the computation described by this context.
    pub fn lde_domain_size(&self) -> usize {
        2usize.pow(self.lde_domain_depth as u32)
    }

    /// Returns modulus of the field for the computation described by this context.
    pub fn field_modulus_bytes(&self) -> &[u8] {
        &self.field_modulus_bytes
    }

    /// Returns number of bits in the base field modulus for the computation described by this
    /// context; the modulus is assumed to be encoded in little-endian byte order.
    pub fn num_modulus_bits(&self) -> u32 {
        let mut num_bits = self.field_modulus_bytes.len() as u32 * 8;
        for &byte in self.field_modulus_bytes.iter().rev() {
            if byte != 0 {
                num_bits -= byte.leading_zeros();
                return num_bits;
            }
            num_bits -= 8;
        }

        0
    }

    /// Returns proof options which were used to a proof in this context.
    pub fn options(&self) -> &ProofOptions {
        &self.options
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this context and appends the resulting bytes to the `target` vector.
    pub fn write_into(&self, target: &mut Vec<u8>) {
        target.push(self.lde_domain_depth);
        assert!(self.field_modulus_bytes.len() < u8::MAX as usize);
        target.push(self.field_modulus_bytes.len() as u8);
        target.extend_from_slice(&self.field_modulus_bytes);
        self.options.write_into(target);
    }
}
