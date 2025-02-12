// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{string::ToString, vec::Vec};

use math::{StarkField, ToElements};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use crate::{ProofOptions, TraceInfo};

// PROOF CONTEXT
// ================================================================================================
/// Basic metadata about a specific execution of a computation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Context {
    trace_info: TraceInfo,
    field_modulus_bytes: Vec<u8>,
    options: ProofOptions,
    num_constraints: usize,
}

impl Context {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new context for a computation described by the specified field, trace info, proof
    /// options, and total number of constraints.
    ///
    /// # Panics
    /// - If either trace length or the LDE domain size implied by the trace length and the blowup
    ///   factor is greater then [u32::MAX].
    /// - If the number of constraints is not greater than 0.
    /// - If the number of constraints is greater than [u32::MAX].
    pub fn new<B: StarkField>(
        trace_info: TraceInfo,
        options: ProofOptions,
        num_constraints: usize,
    ) -> Self {
        // TODO: return errors instead of panicking?

        let trace_length = trace_info.length();
        assert!(trace_length <= u32::MAX as usize, "trace length too big");

        let lde_domain_size = trace_length * options.blowup_factor();
        assert!(lde_domain_size <= u32::MAX as usize, "LDE domain size too big");

        assert!(num_constraints > 0, "number of constraints should be greater than zero");
        assert!(num_constraints <= u32::MAX as usize, "number of constraints is too big");

        Context {
            trace_info,
            field_modulus_bytes: B::get_modulus_le_bytes(),
            options,
            num_constraints,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace info for the computation described by this context.
    pub fn trace_info(&self) -> &TraceInfo {
        &self.trace_info
    }

    /// Returns the size of the LDE domain for the computation described by this context.
    pub fn lde_domain_size(&self) -> usize {
        self.trace_info.length() * self.options.blowup_factor()
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

    /// Returns the total number of constraints.
    pub fn num_constraints(&self) -> usize {
        self.num_constraints
    }
}

impl<E: StarkField> ToElements<E> for Context {
    /// Converts this [Context] into a vector of field elements.
    ///
    /// The elements are laid out as follows:
    /// - trace info:
    ///   - trace segment widths and the number of aux random values [1 element].
    ///   - trace length [1 element].
    ///   - trace metadata [0 or more elements].
    /// - field modulus bytes [2 field elements].
    /// - number of constraints (1 element).
    /// - proof options:
    ///   - field extension, FRI parameters, and grinding factor [1 element].
    ///   - blowup factor [1 element].
    ///   - number of queries [1 element].
    fn to_elements(&self) -> Vec<E> {
        // convert trace layout
        let mut result = self.trace_info.to_elements();

        // convert field modulus bytes into 2 elements
        let num_modulus_bytes = self.field_modulus_bytes.len();
        let (m1, m2) = self.field_modulus_bytes.split_at(num_modulus_bytes / 2);
        result.push(E::from_bytes_with_padding(m1));
        result.push(E::from_bytes_with_padding(m2));

        // convert the number of constraints
        result.push(E::from(self.num_constraints as u32));

        // convert proof options to elements
        result.append(&mut self.options.to_elements());

        result
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for Context {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.trace_info.write_into(target);
        assert!(self.field_modulus_bytes.len() < u8::MAX as usize);
        target.write_u8(self.field_modulus_bytes.len() as u8);
        target.write_bytes(&self.field_modulus_bytes);
        self.options.write_into(target);
        self.num_constraints.write_into(target);
    }
}

impl Deserializable for Context {
    /// Reads proof context from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid Context struct could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // read and validate trace info
        let trace_info = TraceInfo::read_from(source)?;

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

        // read total number of constraints
        let num_constraints = source.read_usize()?;

        Ok(Context {
            trace_info,
            field_modulus_bytes,
            options,
            num_constraints,
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use math::fields::f64::BaseElement;

    use super::{Context, Deserializable, ProofOptions, Serializable, ToElements, TraceInfo};
    use crate::{options::BatchingMethod, FieldExtension};

    #[test]
    fn context_to_elements() {
        let field_extension = FieldExtension::None;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;
        let num_constraints = 128;
        let batching_constraints = BatchingMethod::Linear;
        let batching_deep = BatchingMethod::Linear;

        let main_width = 20;
        let aux_width = 9;
        let aux_rands = 12;
        let trace_length = 4096;

        let ext_fri = u32::from_le_bytes([
            blowup_factor as u8,
            fri_remainder_max_degree,
            fri_folding_factor,
            field_extension as u8,
        ]);

        let expected = {
            let trace_info = TraceInfo::new_multi_segment(
                main_width,
                aux_width,
                aux_rands,
                trace_length,
                vec![],
            );

            let mut expected = trace_info.to_elements();
            expected.extend(vec![
                BaseElement::from(1_u32),    // lower bits of field modulus
                BaseElement::from(u32::MAX), // upper bits of field modulus
                BaseElement::from(num_constraints as u32),
                BaseElement::from(ext_fri),
                BaseElement::from(grinding_factor),
                BaseElement::from(num_queries as u32),
            ]);

            expected
        };

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            batching_constraints,
            batching_deep,
        );
        let trace_info =
            TraceInfo::new_multi_segment(main_width, aux_width, aux_rands, trace_length, vec![]);
        let context = Context::new::<BaseElement>(trace_info, options, num_constraints);
        assert_eq!(expected, context.to_elements());
    }

    #[test]
    fn context_serialization() {
        use math::fields::f64::BaseElement as DummyField;

        let context = Context::new::<DummyField>(
            TraceInfo::new(1, 8),
            ProofOptions::new(
                1,
                2,
                2,
                FieldExtension::None,
                8,
                1,
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            ),
            100,
        );

        let bytes = context.to_bytes();

        let deserialized_context = Context::read_from_bytes(&bytes).unwrap();

        assert_eq!(context, deserialized_context);
    }
}
