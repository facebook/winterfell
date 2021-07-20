// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ProofOptions;
use math::{log2, StarkField};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// CONSTANTS
// ================================================================================================

const MIN_LDE_DOMAIN_SIZE: usize = 16;
const MAX_LDE_DOMAIN_SIZE: usize = 1_099_511_627_776; // 2^40

// PROOF CONTEXT
// ================================================================================================
/// Basic metadata about a specific execution of a computation.
#[derive(Debug, Clone, Eq, PartialEq)]
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
    ///
    /// # Panics
    /// Panics if:
    /// * `lde_domain_size` is less than 16.
    /// * `lde_domain_size` is greater than 2^40.
    /// * `lde_domain_size` is not a power of two.
    pub fn new<B: StarkField>(lde_domain_size: usize, options: ProofOptions) -> Self {
        assert!(
            lde_domain_size >= MIN_LDE_DOMAIN_SIZE,
            "LDE domain must contain at least {} elements, but had {}",
            MIN_LDE_DOMAIN_SIZE,
            lde_domain_size
        );
        assert!(
            lde_domain_size <= MAX_LDE_DOMAIN_SIZE,
            "LDE domain can contain at most {} elements, but had {}",
            MAX_LDE_DOMAIN_SIZE,
            lde_domain_size
        );
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
    /// context.
    ///
    /// The modulus is assumed to be encoded in little-endian byte order.
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
}

impl Serializable for Context {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.lde_domain_depth);
        assert!(self.field_modulus_bytes.len() < u8::MAX as usize);
        target.write_u8(self.field_modulus_bytes.len() as u8);
        target.write_u8_slice(&self.field_modulus_bytes);
        self.options.write_into(target);
    }
}

impl Deserializable for Context {
    /// Reads proof context from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid Context struct could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // read and validate domain depth
        let lde_domain_depth = source.read_u8()?;
        if lde_domain_depth <= log2(MIN_LDE_DOMAIN_SIZE) as u8 {
            return Err(DeserializationError::InvalidValue(format!(
                "LDE domain must contain at least {} elements, but had {}",
                MIN_LDE_DOMAIN_SIZE,
                2usize.pow(lde_domain_depth as u32)
            )));
        }
        if lde_domain_depth >= log2(MAX_LDE_DOMAIN_SIZE) as u8 {
            return Err(DeserializationError::InvalidValue(format!(
                "LDE domain can contain at most {} elements, but had {}",
                MAX_LDE_DOMAIN_SIZE,
                2usize.pow(lde_domain_depth as u32)
            )));
        }

        // read and validate field modulus bytes
        let num_modulus_bytes = source.read_u8()? as usize;
        if num_modulus_bytes == 0 {
            return Err(DeserializationError::InvalidValue(
                "filed modulus cannot be an empty value".to_string(),
            ));
        }
        let field_modulus_bytes = source.read_u8_vec(num_modulus_bytes)?;

        // read options
        let options = ProofOptions::read_from(source)?;

        Ok(Context {
            lde_domain_depth,
            field_modulus_bytes,
            options,
        })
    }
}
