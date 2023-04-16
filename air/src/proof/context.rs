// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{ProofOptions, TraceInfo, TraceLayout};
use math::{StarkField, ToElements};
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

impl<E: StarkField> ToElements<E> for Context {
    /// Converts this [Context] into a vector of field elements.
    ///
    /// The elements are layed out as follows:
    /// - trace layout info [1 or more elements].
    /// - field modulus bytes [2 field elements].
    /// - field extension and FRI parameters [1 element].
    /// - grinding factor [1 element].
    /// - blowup factor [1 element].
    /// - number of queries [1 element].
    /// - trace length [1 element].
    /// - trace metadata [0 or more elements].
    fn to_elements(&self) -> Vec<E> {
        // convert trace layout
        let mut result = self.trace_layout.to_elements();

        // convert field modulus bytes into 2 elements
        let num_modulus_bytes = self.field_modulus_bytes.len();
        let (m1, m2) = self.field_modulus_bytes.split_at(num_modulus_bytes / 2);
        result.push(bytes_to_element(m1));
        result.push(bytes_to_element(m2));

        // convert proof options and trace length to elements
        result.append(&mut self.options.to_elements());
        result.push(E::from(self.trace_length as u64));

        // convert trace metadata to elements; this is done by breaking trace metadata into chunks
        // of bytes which are slightly smaller than the number of bytes needed to encode a field
        // element, and then converting these chunks into field elements.
        if !self.trace_meta.is_empty() {
            for chunk in self.trace_meta.chunks(E::ELEMENT_BYTES - 1) {
                result.push(bytes_to_element(chunk));
            }
        }

        result
    }
}

impl Serializable for Context {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.trace_layout.write_into(target);
        target.write_u8(self.trace_length.ilog2() as u8); // store as power of two
        target.write_u16(self.trace_meta.len() as u16);
        target.write_bytes(&self.trace_meta);
        assert!(self.field_modulus_bytes.len() < u8::MAX as usize);
        target.write_u8(self.field_modulus_bytes.len() as u8);
        target.write_bytes(&self.field_modulus_bytes);
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
        if trace_length < TraceInfo::MIN_TRACE_LENGTH.ilog2() as u8 {
            return Err(DeserializationError::InvalidValue(format!(
                "trace length cannot be smaller than 2^{}, but was 2^{}",
                TraceInfo::MIN_TRACE_LENGTH.ilog2(),
                trace_length
            )));
        }
        let trace_length = 2_usize.pow(trace_length as u32);

        // read trace metadata
        let num_meta_bytes = source.read_u16()? as usize;
        let trace_meta = if num_meta_bytes != 0 {
            source.read_vec(num_meta_bytes)?
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
        let field_modulus_bytes = source.read_vec(num_modulus_bytes)?;

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

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a slice of bytes into a field element.
///
/// Assumes that the length of `bytes` is smaller than the number of bytes needed to encode an
/// element.
#[allow(clippy::let_and_return)]
fn bytes_to_element<B: StarkField>(bytes: &[u8]) -> B {
    debug_assert!(bytes.len() < B::ELEMENT_BYTES);

    let mut buf = bytes.to_vec();
    buf.resize(B::ELEMENT_BYTES, 0);
    let element = match B::try_from(&buf) {
        Ok(element) => element,
        Err(_) => panic!("element deserialization failed"),
    };
    element
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{Context, ProofOptions, ToElements, TraceInfo};
    use crate::{FieldExtension, TraceLayout};
    use math::fields::f64::BaseElement;

    #[test]
    fn context_to_elements() {
        let field_extension = FieldExtension::None;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;

        let main_width = 20;
        let num_aux_segments = 1;
        let aux_width = 9;
        let aux_rands = 12;
        let trace_length = 4096;

        let ext_fri = u32::from_le_bytes([
            fri_remainder_max_degree,
            fri_folding_factor,
            field_extension as u8,
            0,
        ]);

        let layout_info = u32::from_le_bytes([aux_rands, aux_width, num_aux_segments, main_width]);

        let expected = vec![
            BaseElement::from(layout_info),
            BaseElement::from(1_u32),    // lower bits of field modulus
            BaseElement::from(u32::MAX), // upper bits of field modulus
            BaseElement::from(ext_fri),
            BaseElement::from(grinding_factor as u32),
            BaseElement::from(blowup_factor as u32),
            BaseElement::from(num_queries as u32),
            BaseElement::from(trace_length as u32),
        ];

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
        );
        let layout = TraceLayout::new(
            main_width as usize,
            [aux_width as usize],
            [aux_rands as usize],
        );
        let trace_info = TraceInfo::new_multi_segment(layout, trace_length, vec![]);
        let context = Context::new::<BaseElement>(&trace_info, options);
        assert_eq!(expected, context.to_elements());
    }
}
