// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::{bytes_to_element_with_padding, log2, StarkField, ToElements};
use utils::{
    collections::Vec, string::ToString, ByteReader, ByteWriter, Deserializable,
    DeserializationError, Serializable,
};

// CONSTANTS
// ================================================================================================

/// Number of allowed auxiliary trace segments.
const NUM_AUX_SEGMENTS: usize = 1;

// TRACE INFO
// ================================================================================================
/// Information about a specific execution trace.
///
/// Trace info consists of trace layout info, length, and optional custom metadata. Trace layout
/// specifies the number of columns for all trace segments. Currently, a trace can consist of at
/// most two segments. Metadata is just a vector of bytes and can store any values up to 64KB in
/// size.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TraceInfo {
    main_segment_width: usize,
    aux_segment_widths: [usize; NUM_AUX_SEGMENTS],
    aux_segment_rands: [usize; NUM_AUX_SEGMENTS],
    lagrange_kernel_aux_column_idx: Option<usize>,
    num_aux_segments: usize,
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
    /// Maximum number of random elements per auxiliary trace segment; currently set to 255.
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
        Self::new_multi_segment(width, [0], [0], None, length, meta)
    }

    /// Creates a new [TraceInfo] from the specified trace segment widths, length, and metadata.
    ///
    /// # Panics
    /// Panics if:
    /// * The width of the first trace segment is zero.
    /// * Total width of all trace segments is greater than 255.
    /// * Trace length is smaller than 8 or is not a power of two.
    pub fn new_multi_segment(
        main_segment_width: usize,
        aux_segment_widths: [usize; NUM_AUX_SEGMENTS],
        aux_segment_rands: [usize; NUM_AUX_SEGMENTS],
        lagrange_kernel_aux_column_idx: Option<usize>,
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
        let full_width = main_segment_width + aux_segment_widths.iter().sum::<usize>();
        assert!(
            full_width <= TraceInfo::MAX_TRACE_WIDTH,
            "total number of columns in the trace cannot be greater than {}, but was {}",
            TraceInfo::MAX_TRACE_WIDTH,
            full_width
        );

        // validate number of random elements required by each segment
        let mut was_zero_width = false;
        let mut num_aux_segments = 0;
        for (&width, &num_rand_elements) in aux_segment_widths.iter().zip(aux_segment_rands.iter())
        {
            if width != 0 {
                assert!(
                    !was_zero_width,
                    "a non-empty trace segment cannot follow an empty segment"
                );
                assert!(
                    num_rand_elements > 0,
                    "number of random elements for a non-empty trace segment must be greater than zero"
                );
                num_aux_segments += 1;
            } else {
                assert!(
                    num_rand_elements == 0,
                    "number of random elements for an empty trace segment must be zero"
                );
                was_zero_width = true;
            }
            assert!(
                num_rand_elements <= TraceInfo::MAX_RAND_SEGMENT_ELEMENTS,
                "number of random elements required by a segment cannot exceed {}, but was {}",
                TraceInfo::MAX_RAND_SEGMENT_ELEMENTS,
                num_rand_elements
            );
        }

        // validate Lagrange kernel aux column, if any
        if let Some(lagrange_kernel_aux_column_idx) = lagrange_kernel_aux_column_idx {
            assert!(lagrange_kernel_aux_column_idx < aux_segment_widths[0], "Lagrange kernel column index out of bounds: index={}, but only {} columns in segment", lagrange_kernel_aux_column_idx, aux_segment_widths[0]);

            let min_aux_segment_rands = log2(trace_length);
            assert!(aux_segment_rands[0] >= min_aux_segment_rands as usize, "Lagrange kernel column requires log(trace_length) random elements. Got: {}, but need at least {}", aux_segment_rands[0], min_aux_segment_rands);
        }

        TraceInfo {
            main_segment_width,
            aux_segment_widths,
            aux_segment_rands,
            lagrange_kernel_aux_column_idx,
            num_aux_segments,
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
        self.main_segment_width + self.aux_segment_widths[0]
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

    /// Returns true if an execution trace contains more than one segment.
    pub fn is_multi_segment(&self) -> bool {
        self.num_aux_segments > 0
    }

    /// Returns the number of columns in the main segment of an execution trace.
    ///
    /// This is guaranteed to be between 1 and 255.
    pub fn main_trace_width(&self) -> usize {
        self.main_segment_width
    }

    /// Returns the number of columns in all auxiliary segments of an execution trace.
    pub fn aux_trace_width(&self) -> usize {
        self.aux_segment_widths.iter().sum()
    }

    /// Returns the index of the auxiliary column which implements the Lagrange kernel, if any
    pub fn lagrange_kernel_aux_column_idx(&self) -> Option<usize> {
        self.lagrange_kernel_aux_column_idx
    }

    /// Returns the total number of segments in an execution trace.
    pub fn num_segments(&self) -> usize {
        self.num_aux_segments + 1
    }

    /// Returns the number of auxiliary trace segments in an execution trace.
    pub fn num_aux_segments(&self) -> usize {
        self.num_aux_segments
    }

    /// Returns the number of columns in the auxiliary trace segment at the specified index.
    pub fn get_aux_segment_width(&self, segment_idx: usize) -> usize {
        assert!(
            segment_idx < self.num_aux_segments,
            "attempted to access segment index {segment_idx}, but there are only {} segments",
            self.num_aux_segments
        );

        self.aux_segment_widths[segment_idx]
    }

    /// Returns the number of random elements required by the auxiliary trace segment at the
    /// specified index.
    pub fn get_aux_segment_rand_elements(&self, segment_idx: usize) -> usize {
        // TODO: panic if segment_idx is not within num_aux_segments
        self.aux_segment_rands[segment_idx]
    }
}

impl<E: StarkField> ToElements<E> for TraceInfo {
    fn to_elements(&self) -> Vec<E> {
        let mut result = Vec::new();

        // main segment width, number of auxiliary segments, and parameters of the first auxiliary
        // segment (if present) go into the first field element; we assume that each parameter can
        // be encoded in 8 bits (which is enforced by the constructor)
        let mut buf = self.main_segment_width as u32;
        buf = (buf << 8) | self.num_aux_segments as u32;
        if self.num_aux_segments == 1 {
            buf = (buf << 8) | self.aux_segment_widths[0] as u32;
            buf = (buf << 8) | self.aux_segment_rands[0] as u32;
        }
        result.push(E::from(buf));

        // parameters of all subsequent auxiliary segments go into additional elements
        for i in 1..self.num_aux_segments {
            buf = self.aux_segment_widths[i] as u32;
            buf = (buf << 8) | self.aux_segment_rands[i] as u32;
            result.push(E::from(buf));
        }

        result.push(E::from(self.trace_length as u32));

        // convert trace metadata to elements; this is done by breaking trace metadata into chunks
        // of bytes which are slightly smaller than the number of bytes needed to encode a field
        // element, and then converting these chunks into field elements.
        if !self.trace_meta.is_empty() {
            for chunk in self.trace_meta.chunks(E::ELEMENT_BYTES - 1) {
                result.push(bytes_to_element_with_padding(chunk.to_vec()));
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
        for &w in self.aux_segment_widths.iter() {
            debug_assert!(w <= u8::MAX as usize, "aux segment width does not fit into u8 value");
            target.write_u8(w as u8);
        }
        for &rc in self.aux_segment_rands.iter() {
            debug_assert!(
                rc <= u8::MAX as usize,
                "aux segment random element count does not fit into u8 value"
            );
            target.write_u8(rc as u8);
        }

        // store lagrange kernel column idx
        target.write_bool(self.lagrange_kernel_aux_column_idx.is_some());
        if let Some(lagrange_kernel_aux_column_idx) = self.lagrange_kernel_aux_column_idx {
            target.write_u32(lagrange_kernel_aux_column_idx as u32);
        }

        // store trace length as power of two
        target.write_u8(self.trace_length.ilog2() as u8);

        // store trace meta
        target.write_u16(self.trace_meta.len() as u16);
        target.write_bytes(&self.trace_meta);
    }
}

impl Deserializable for TraceInfo {
    /// Reads [TraceLayout] from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid [TraceLayout] struct could not be read from the specified
    /// `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let main_segment_width = source.read_u8()? as usize;
        if main_segment_width == 0 {
            return Err(DeserializationError::InvalidValue(
                "main trace segment width must be greater than zero".to_string(),
            ));
        }

        // read and validate auxiliary trace segment widths
        let mut was_zero_width = false;
        let mut aux_segment_widths = [0; NUM_AUX_SEGMENTS];
        for width in aux_segment_widths.iter_mut() {
            *width = source.read_u8()? as usize;
            if *width != 0 {
                if was_zero_width {
                    return Err(DeserializationError::InvalidValue(
                        "a non-empty trace segment cannot follow an empty segment".to_string(),
                    ));
                }
            } else {
                was_zero_width = true;
            }
        }

        let full_trace_width = main_segment_width + aux_segment_widths.iter().sum::<usize>();
        if full_trace_width >= TraceInfo::MAX_TRACE_WIDTH {
            return Err(DeserializationError::InvalidValue(format!(
                "full trace width cannot be greater than {}, but was {}",
                TraceInfo::MAX_TRACE_WIDTH,
                full_trace_width
            )));
        }

        // read and validate number of random elements for each auxiliary trace segment
        let mut aux_segment_rands = [0; NUM_AUX_SEGMENTS];
        for (num_rand_elements, &width) in
            aux_segment_rands.iter_mut().zip(aux_segment_widths.iter())
        {
            *num_rand_elements = source.read_u8()? as usize;
            if width == 0 && *num_rand_elements != 0 {
                return Err(DeserializationError::InvalidValue(
                    "an empty trace segment cannot require random elements".to_string(),
                ));
            } else if width != 0 && *num_rand_elements == 0 {
                return Err(DeserializationError::InvalidValue(
                    "a non-empty trace segment must require at least one random element"
                        .to_string(),
                ));
            } else if *num_rand_elements > TraceInfo::MAX_RAND_SEGMENT_ELEMENTS {
                return Err(DeserializationError::InvalidValue(format!(
                    "number of random elements required by a segment cannot exceed {}, but was {}",
                    TraceInfo::MAX_RAND_SEGMENT_ELEMENTS,
                    *num_rand_elements
                )));
            }
        }

        // read Lagrange kernel column index
        let has_lagrange_kernel_column_idx = source.read_bool()?;
        let lagrange_kernel_aux_column_idx = if has_lagrange_kernel_column_idx {
            Some(source.read_u32()? as usize)
        } else {
            None
        };

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
            aux_segment_widths,
            aux_segment_rands,
            lagrange_kernel_aux_column_idx,
            trace_length,
            trace_meta,
        ))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{ToElements, TraceInfo};
    use math::{fields::f64::BaseElement, FieldElement};

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
            [aux_width as usize],
            [aux_rands as usize],
            None,
            trace_length as usize,
            trace_meta,
        );

        assert_eq!(expected, info.to_elements());
    }
}
