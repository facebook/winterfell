// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{ProofOptions, TraceInfo, TraceLayout};
use math::StarkField;
use utils::{
    collections::Vec, string::ToString, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Serializable,
};

// PROOF CONTEXT
// ================================================================================================
/// Basic metadata about a specific execution of a computation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Context {
    trace_layout: TraceLayout,
    trace_length: usize,
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
            trace_layout: trace_info.layout().clone(),
            trace_length: trace_info.length(),
            trace_meta: trace_info.meta().to_vec(),
            field_modulus_bytes: B::get_modulus_le_bytes(),
            options,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a layout describing how columns of the execution trace described by this context
    /// are arranged into segments.
    pub fn trace_layout(&self) -> &TraceLayout {
        &self.trace_layout
    }

    /// Returns execution trace length of the computation described by this context.
    pub fn trace_length(&self) -> usize {
        self.trace_length
    }

    /// Returns execution trace info for the computation described by this context.
    pub fn get_trace_info(&self) -> TraceInfo {
        TraceInfo::new_multi_segment(
            self.trace_layout.clone(),
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
        self.trace_layout.write_into(target);
        target.write_u8(math::log2(self.trace_length) as u8); // store as power of two
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
        // read and validate trace layout info
        let trace_layout = TraceLayout::read_from(source)?;

        // read and validate trace length (which was stored as a power of two)
        let trace_length = source.read_u8()?;
        if trace_length < math::log2(TraceInfo::MIN_TRACE_LENGTH) as u8 {
            return Err(DeserializationError::InvalidValue(format!(
                "trace length cannot be smaller than 2^{}, but was 2^{}",
                math::log2(TraceInfo::MIN_TRACE_LENGTH),
                trace_length
            )));
        }
        let trace_length = 2_usize.pow(trace_length as u32);

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
            trace_layout,
            trace_length,
            trace_meta,
            field_modulus_bytes,
            options,
        })
    }
}
