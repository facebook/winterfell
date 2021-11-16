// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{ProofOptions, TraceInfo};
use math::{log2, StarkField};
use utils::{
    collections::Vec, string::ToString, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Serializable,
};

// PROOF CONTEXT
// ================================================================================================
/// Basic metadata about a specific execution of a computation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Context {
    trace_width: u8,
    trace_length: u8, // stored as power of two
    trace_meta: Vec<u8>,
    field_modulus_bytes: Vec<u8>,
    options: ProofOptions,
}

impl Context {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new context for a computation described by the specified field, trace info, and
    /// proof options.
    pub fn new<B: StarkField>(trace_info: &TraceInfo, options: ProofOptions) -> Self {
        Context {
            trace_width: trace_info.width() as u8,
            trace_length: log2(trace_info.length()) as u8,
            trace_meta: trace_info.meta().to_vec(),
            field_modulus_bytes: B::get_modulus_le_bytes(),
            options,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace length of the computation described by this context.
    pub fn trace_length(&self) -> usize {
        2_usize.pow(self.trace_length as u32)
    }

    /// Returns execution trace width of the computation described by this context.
    pub fn trace_width(&self) -> usize {
        self.trace_width as usize
    }

    /// Returns execution trace info for the computation described by this context.
    pub fn get_trace_info(&self) -> TraceInfo {
        TraceInfo::with_meta(
            self.trace_width(),
            self.trace_length(),
            self.trace_meta.clone(),
        )
    }

    /// Returns the size of the LDE domain for the computation described by this context.
    pub fn lde_domain_size(&self) -> usize {
        self.trace_length() * self.options.blowup_factor()
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
        target.write_u8(self.trace_width);
        target.write_u8(self.trace_length);
        target.write_u16(self.trace_meta.len() as u16);
        target.write_u8_slice(&self.trace_meta);
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
        // read and validate trace width
        let trace_width = source.read_u8()?;
        if trace_width == 0 {
            return Err(DeserializationError::InvalidValue(
                "trace width must be greater than zero".to_string(),
            ));
        }
        if trace_width as usize >= TraceInfo::MAX_TRACE_WIDTH {
            return Err(DeserializationError::InvalidValue(format!(
                "Trace width cannot be greater than {}, but had {}",
                TraceInfo::MAX_TRACE_WIDTH,
                trace_width
            )));
        }

        // read and validate trace length
        let trace_length = source.read_u8()?;
        if 2_usize.pow(trace_length as u32) < TraceInfo::MIN_TRACE_LENGTH {
            return Err(DeserializationError::InvalidValue(format!(
                "Trace length cannot be smaller than {}, but had {}",
                TraceInfo::MIN_TRACE_LENGTH,
                2_usize.pow(trace_length as u32)
            )));
        }

        // read trace metadata
        let num_meta_bytes = source.read_u16()? as usize;
        let trace_meta = if num_meta_bytes != 0 {
            source.read_u8_vec(num_meta_bytes)?
        } else {
            vec![]
        };

        // read and validate field modulus bytes
        let num_modulus_bytes = source.read_u8()? as usize;
        if num_modulus_bytes == 0 {
            return Err(DeserializationError::InvalidValue(
                "field modulus cannot be an empty value".to_string(),
            ));
        }
        let field_modulus_bytes = source.read_u8_vec(num_modulus_bytes)?;

        // read options
        let options = ProofOptions::read_from(source)?;

        Ok(Context {
            trace_width,
            trace_length,
            trace_meta,
            field_modulus_bytes,
            options,
        })
    }
}
