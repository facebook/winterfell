// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{string::ToString, vec::Vec};

use math::{StarkField, ToElements};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// CONSTANTS
// ================================================================================================

// TRACE INFO
// ================================================================================================
/// Information about a specific execution trace.
///
/// Trace info consists of the number of columns for all trace segments, trace length, the number of
/// random elements needed to generate the auxiliary segment and optional custom metadata.
///
/// Currently, a trace can consist of at most two segments: the main segment and one auxiliary
/// segment. Metadata is just a vector of bytes and can store any values up to 64KB in size.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TraceInfo {
    main_segment_width: usize,
    aux_segment_width: usize,
    num_aux_segment_rands: usize,
    trace_length: usize,
    trace_meta: Vec<u8>,
}

impl TraceInfo {
    /// Smallest allowed execution trace length; currently set at 8.
    pub const MIN_TRACE_LENGTH: usize = 8;
    /// Maximum number of columns in an execution trace (across all segments); currently set at 255.
    pub const MAX_TRACE_WIDTH: usize = 255;
    /// Maximum number of bytes in trace metadata; currently set at 65535.
    pub const MAX_META_LENGTH: usize = 65535;
    /// Maximum number of random elements in the auxiliary trace segment; currently set to 255.
    pub const MAX_RAND_SEGMENT_ELEMENTS: usize = 255;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [TraceInfo] from the specified trace width and length.
    ///
    /// An execution trace described by this trace info is limited to a single segment.
    ///
    /// # Panics
    /// Panics if:
    /// * Trace width is zero or greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    pub fn new(width: usize, length: usize) -> Self {
        Self::with_meta(width, length, vec![])
    }

    /// Creates a new [TraceInfo] from the specified trace width, length, and metadata.
    ///
    /// An execution trace described by this trace info is limited to a single segment.
    ///
    /// # Panics
    /// Panics if:
    /// * Trace width is zero or greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    /// * Length of `meta` is greater than 65535;
    pub fn with_meta(width: usize, length: usize, meta: Vec<u8>) -> Self {
        assert!(width > 0, "trace width must be greater than 0");
        Self::new_multi_segment(width, 0, 0, length, meta)
    }

    /// Creates a new [TraceInfo] with main and auxiliary segments.
    ///
    /// # Panics
    /// Panics if:
    /// * The width of the first trace segment is zero.
    /// * Total width of all trace segments is greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    /// * A zero entry in auxiliary segment width array is followed by a non-zero entry.
    /// * Number of random elements for the auxiliary trace segment of non-zero width is set to
    ///   zero.
    /// * Number of random elements for the auxiliary trace segment of zero width is set to
    ///   non-zero.
    /// * Number of random elements for any auxiliary trace segment is greater than 255.
    pub fn new_multi_segment(
        main_segment_width: usize,
        aux_segment_width: usize,
        num_aux_segment_rands: usize,
        trace_length: usize,
        trace_meta: Vec<u8>,
    ) -> Self {
        assert!(
            trace_length >= Self::MIN_TRACE_LENGTH,
            "trace length must be at least {}, but was {}",
            Self::MIN_TRACE_LENGTH,
            trace_length
        );
        assert!(
            trace_length.is_power_of_two(),
            "trace length must be a power of two, but was {trace_length}"
        );
        assert!(
            trace_meta.len() <= Self::MAX_META_LENGTH,
            "number of metadata bytes cannot be greater than {}, but was {}",
            Self::MAX_META_LENGTH,
            trace_meta.len()
        );

        // validate trace segment widths
        assert!(main_segment_width > 0, "main trace segment must consist of at least one column");
        let full_width = main_segment_width + aux_segment_width;
        assert!(
            full_width <= TraceInfo::MAX_TRACE_WIDTH,
            "total number of columns in the trace cannot be greater than {}, but was {}",
            TraceInfo::MAX_TRACE_WIDTH,
            full_width
        );

        // validate number of random elements required by the auxiliary segment
        if aux_segment_width == 0 {
            assert!(
                num_aux_segment_rands == 0,
                "number of random elements for an empty auxiliary trace segment must be zero"
            );
        }
        assert!(
            num_aux_segment_rands <= TraceInfo::MAX_RAND_SEGMENT_ELEMENTS,
            "number of random elements required by a segment cannot exceed {}, but was {}",
            TraceInfo::MAX_RAND_SEGMENT_ELEMENTS,
            num_aux_segment_rands
        );

        TraceInfo {
            main_segment_width,
            aux_segment_width,
            num_aux_segment_rands,
            trace_length,
            trace_meta,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the total number of columns in an execution trace.
    ///
    /// This is guaranteed to be between 1 and 255.
    pub fn width(&self) -> usize {
        self.main_segment_width + self.aux_segment_width
    }

    /// Returns execution trace length.
    ///
    /// The length is guaranteed to be a power of two.
    pub fn length(&self) -> usize {
        self.trace_length
    }

    /// Returns execution trace metadata.
    pub fn meta(&self) -> &[u8] {
        &self.trace_meta
    }

    /// Returns true if an execution trace contains the auxiliary trace segment.
    pub fn is_multi_segment(&self) -> bool {
        self.aux_segment_width > 0
    }

    /// Returns the number of columns in the main segment of an execution trace.
    ///
    /// This is guaranteed to be between 1 and 255.
    pub fn main_trace_width(&self) -> usize {
        self.main_segment_width
    }

    /// Returns the number of columns in the auxiliary segment of an execution trace.
    pub fn aux_segment_width(&self) -> usize {
        self.aux_segment_width
    }

    /// Returns the total number of segments in an execution trace.
    pub fn num_segments(&self) -> usize {
        if self.is_multi_segment() {
            2
        } else {
            1
        }
    }

    /// Returns the number of auxiliary trace segments in an execution trace.
    pub fn num_aux_segments(&self) -> usize {
        if self.is_multi_segment() {
            1
        } else {
            0
        }
    }

    /// Returns the number of columns in the auxiliary trace segment.
    pub fn get_aux_segment_width(&self) -> usize {
        self.aux_segment_width
    }

    /// Returns the number of random elements needed to build all auxiliary columns.
    pub fn get_num_aux_segment_rand_elements(&self) -> usize {
        self.num_aux_segment_rands
    }
}

impl<E: StarkField> ToElements<E> for TraceInfo {
    fn to_elements(&self) -> Vec<E> {
        let mut result = Vec::new();

        // main segment width, number of auxiliary segments, and parameters of the first auxiliary
        // segment (if present) go into the first field element; we assume that each parameter can
        // be encoded in 8 bits (which is enforced by the constructor)
        let mut buf = self.main_segment_width as u32;
        buf = (buf << 8) | self.num_aux_segments() as u32;
        if self.num_aux_segments() == 1 {
            buf = (buf << 8) | self.aux_segment_width as u32;
            buf = (buf << 8) | self.num_aux_segment_rands as u32;
        }
        result.push(E::from(buf));

        // We assume here that the trace length is never greater than 2^32.
        result.push(E::from(self.trace_length as u32));

        // convert trace metadata to elements; this is done by breaking trace metadata into chunks
        // of bytes which are slightly smaller than the number of bytes needed to encode a field
        // element, and then converting these chunks into field elements.
        if !self.trace_meta.is_empty() {
            for chunk in self.trace_meta.chunks(E::ELEMENT_BYTES - 1) {
                result.push(E::from_bytes_with_padding(chunk));
            }
        }

        result
    }
}

impl Serializable for TraceInfo {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // store segments
        target.write_u8(self.main_segment_width as u8);

        debug_assert!(
            self.aux_segment_width <= u8::MAX as usize,
            "aux segment width does not fit into u8 value"
        );
        target.write_u8(self.aux_segment_width as u8);
        debug_assert!(
            self.num_aux_segment_rands <= u8::MAX as usize,
            "aux segment random element count does not fit into u8 value"
        );
        target.write_u8(self.num_aux_segment_rands as u8);

        // store trace length as power of two
        target.write_u8(self.trace_length.ilog2() as u8);

        // store trace meta
        target.write_u16(self.trace_meta.len() as u16);
        target.write_bytes(&self.trace_meta);
    }
}

impl Deserializable for TraceInfo {
    /// Reads [`TraceInfo`] from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid [`TraceInfo`] struct could not be read from the specified
    /// `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let main_segment_width = source.read_u8()? as usize;
        if main_segment_width == 0 {
            return Err(DeserializationError::InvalidValue(
                "main trace segment width must be greater than zero".to_string(),
            ));
        }

        // read auxiliary trace segment width
        let aux_segment_width = source.read_u8()? as usize;

        let full_trace_width = main_segment_width + aux_segment_width;
        if full_trace_width >= TraceInfo::MAX_TRACE_WIDTH {
            return Err(DeserializationError::InvalidValue(format!(
                "full trace width cannot be greater than {}, but was {}",
                TraceInfo::MAX_TRACE_WIDTH,
                full_trace_width
            )));
        }

        // read and validate number of random elements for the auxiliary trace segment
        let num_aux_segment_rands = source.read_u8()? as usize;
        if aux_segment_width != 0 && num_aux_segment_rands == 0 {
            return Err(DeserializationError::InvalidValue(
                "a non-empty trace segment must require at least one random element".to_string(),
            ));
        } else if num_aux_segment_rands > TraceInfo::MAX_RAND_SEGMENT_ELEMENTS {
            return Err(DeserializationError::InvalidValue(format!(
                "number of random elements required by a segment cannot exceed {}, but was {}",
                TraceInfo::MAX_RAND_SEGMENT_ELEMENTS,
                num_aux_segment_rands
            )));
        }

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

        Ok(Self::new_multi_segment(
            main_segment_width,
            aux_segment_width,
            num_aux_segment_rands,
            trace_length,
            trace_meta,
        ))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use math::{fields::f64::BaseElement, FieldElement};

    use super::{ToElements, TraceInfo};

    #[test]
    fn trace_info_to_elements() {
        // --- test trace with only main segment ------------------------------
        let main_width = 20;
        let trace_length = 64_u32;
        let num_aux_segments = 0;

        let expected = {
            let first_ele = u32::from_le_bytes([num_aux_segments, main_width as u8, 0, 0]);

            vec![BaseElement::from(first_ele), BaseElement::from(trace_length)]
        };

        let info = TraceInfo::new(main_width, trace_length as usize);
        assert_eq!(expected, info.to_elements());

        // --- test trace with one auxiliary segment --------------------------
        let main_width = 20;
        let trace_length = 64_u32;
        let num_aux_segments = 1;
        let aux_width = 9;
        let aux_rands = 12;
        let trace_meta = vec![1_u8, 2, 3, 4];

        let expected = {
            let first_ele =
                u32::from_le_bytes([aux_rands as u8, aux_width, num_aux_segments, main_width]);

            // `trace_meta` is 4 bytes, so fits into a single element
            let mut meta_bytes = trace_meta.clone();
            meta_bytes.resize(BaseElement::ELEMENT_BYTES, 0);
            let meta_ele = BaseElement::try_from(meta_bytes.as_slice()).unwrap();

            vec![BaseElement::from(first_ele), BaseElement::from(trace_length), meta_ele]
        };

        let info = TraceInfo::new_multi_segment(
            main_width as usize,
            aux_width as usize,
            aux_rands,
            trace_length as usize,
            trace_meta,
        );

        assert_eq!(expected, info.to_elements());
    }
}
