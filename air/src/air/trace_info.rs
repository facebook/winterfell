// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use math::{StarkField, ToElements};
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
    layout: TraceLayout,
    length: usize,
    meta: Vec<u8>,
}

impl TraceInfo {
    /// Smallest allowed execution trace length; currently set at 4.
    pub const MIN_TRACE_LENGTH: usize = 4;
    /// Maximum number of columns in an execution trace (across all segments); currently set at 65535.
    pub const MAX_TRACE_WIDTH: usize = 65535;
    /// Maximum number of bytes in trace metadata; currently set at 65535.
    pub const MAX_META_LENGTH: usize = 65535;
    /// Maximum number of random elements per auxiliary trace segment; currently set to 65535.
    pub const MAX_RAND_SEGMENT_ELEMENTS: usize = 65535;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [TraceInfo] from the specified trace width and length.
    ///
    /// An execution trace described by this trace info is limited to a single segment.
    ///
    /// # Panics
    /// Panics if:
    /// * Trace width is zero or greater than 65535.
    /// * Trace length is smaller than 4 or is not a power of two.
    pub fn new(width: usize, length: usize) -> Self {
        Self::with_meta(width, length, vec![])
    }

    /// Creates a new [TraceInfo] from the specified trace width, length, and metadata.
    ///
    /// An execution trace described by this trace info is limited to a single segment.
    ///
    /// # Panics
    /// Panics if:
    /// * Trace width is zero or greater than 25655355.
    /// * Trace length is smaller than 4 or is not a power of two.
    /// * Length of `meta` is greater than 65535;
    pub fn with_meta(width: usize, length: usize, meta: Vec<u8>) -> Self {
        assert!(width > 0, "trace width must be greater than 0");
        let layout = TraceLayout::new(width, [0], [0]);
        Self::new_multi_segment(layout, length, meta)
    }

    /// Creates a new [TraceInfo] from the specified trace segment widths, length, and metadata.
    ///
    /// # Panics
    /// Panics if:
    /// * The width of the first trace segment is zero.
    /// * Total width of all trace segments is greater than 65535.
    /// * Trace length is smaller than 4 or is not a power of two.
    pub fn new_multi_segment(layout: TraceLayout, length: usize, meta: Vec<u8>) -> Self {
        assert!(
            length >= Self::MIN_TRACE_LENGTH,
            "trace length must be at least {}, but was {}",
            Self::MIN_TRACE_LENGTH,
            length
        );
        assert!(
            length.is_power_of_two(),
            "trace length must be a power of two, but was {length}"
        );
        assert!(
            meta.len() <= Self::MAX_META_LENGTH,
            "number of metadata bytes cannot be greater than {}, but was {}",
            Self::MAX_META_LENGTH,
            meta.len()
        );
        TraceInfo {
            layout,
            length,
            meta,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a description of how execution trace columns are arranged into segments.
    ///
    /// Currently, an execution trace can consist of at most two segments.
    pub fn layout(&self) -> &TraceLayout {
        &self.layout
    }

    /// Returns the total number of columns in an execution trace.
    ///
    /// This is guaranteed to be between 1 and 65535.
    pub fn width(&self) -> usize {
        self.layout.main_trace_width() + self.layout().aux_trace_width()
    }

    /// Returns execution trace length.
    ///
    /// The length is guaranteed to be a power of two.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Returns execution trace metadata.
    pub fn meta(&self) -> &[u8] {
        &self.meta
    }

    /// Returns true if an execution trace contains more than one segment.
    pub fn is_multi_segment(&self) -> bool {
        self.layout.num_aux_segments > 0
    }
}

// TRACE LAYOUT
// ================================================================================================

/// Layout of columns within an execution trace.
///
/// A layout describes how columns of a trace are arranged into segments. All execution traces must
/// have a non-zero main segment, and may have additional auxiliary trace segments. Currently, the
/// number of auxiliary trace segments is limited to one.
///
/// Additionally, a layout contains information on how many random elements are required to build a
/// given auxiliary trace segment. This information is used to construct
/// [AuxTraceRandElements](crate::AuxTraceRandElements) struct which is passed in as one of the
/// parameters to [Air::evaluate_aux_transition()](crate::Air::evaluate_aux_transition()) and
/// [Air::get_aux_assertions()](crate::Air::get_aux_assertions()) methods.
///
/// The number of random elements may be different from the number of columns in a given auxiliary
/// segment. For example, an auxiliary segment may contain just one column, but may require many
/// random elements.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TraceLayout {
    main_segment_width: usize,
    aux_segment_widths: [usize; NUM_AUX_SEGMENTS],
    aux_segment_rands: [usize; NUM_AUX_SEGMENTS],
    num_aux_segments: usize,
}

impl TraceLayout {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [TraceLayout] instantiated with the provided info.
    ///
    /// # Panics
    /// Panics if:
    /// * Width of the main trace segment is set to zero.
    /// * Sum of all segment widths exceeds 65535.
    /// * A zero entry in auxiliary segment width array is followed by a non-zero entry.
    /// * Number of random elements for an auxiliary trace segment of non-zero width is set to zero.
    /// * Number of random elements for an auxiliary trace segment of zero width is set to non-zero.
    /// * Number of random elements for any auxiliary trace segment is greater than 65535.
    pub fn new(
        main_width: usize,
        aux_widths: [usize; NUM_AUX_SEGMENTS],
        aux_rands: [usize; NUM_AUX_SEGMENTS],
    ) -> Self {
        // validate trace segment widths
        assert!(
            main_width > 0,
            "main trace segment must consist of at least one column"
        );
        let full_width = main_width + aux_widths.iter().sum::<usize>();
        assert!(
            full_width <= TraceInfo::MAX_TRACE_WIDTH,
            "total number of columns in the trace cannot be greater than {}, but was {}",
            TraceInfo::MAX_TRACE_WIDTH,
            full_width
        );

        // validate number of random elements required by each segment
        let mut was_zero_width = false;
        let mut num_aux_segments = 0;
        for (&width, &num_rand_elements) in aux_widths.iter().zip(aux_rands.iter()) {
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

        Self {
            main_segment_width: main_width,
            aux_segment_widths: aux_widths,
            aux_segment_rands: aux_rands,
            num_aux_segments,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in the main segment of an execution trace.
    ///
    /// This is guaranteed to be between 1 and 65535.
    pub fn main_trace_width(&self) -> usize {
        self.main_segment_width
    }

    /// Returns the number of columns in all auxiliary segments of an execution trace.
    pub fn aux_trace_width(&self) -> usize {
        self.aux_segment_widths.iter().sum()
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
        // TODO: panic if segment_idx is not within num_aux_segments
        self.aux_segment_widths[segment_idx]
    }

    /// Returns the number of random elements required by the auxiliary trace segment at the
    /// specified index.
    pub fn get_aux_segment_rand_elements(&self, segment_idx: usize) -> usize {
        // TODO: panic if segment_idx is not within num_aux_segments
        self.aux_segment_rands[segment_idx]
    }
}

impl<E: StarkField> ToElements<E> for TraceLayout {
    fn to_elements(&self) -> Vec<E> {
        let mut result = Vec::new();

        // main segment width, number of auxiliary segments, and parameters of the first auxiliary
        // segment (if present) go into the first field element; we assume that each parameter can
        // be encoded in 16 bits (which is enforced by the constructor)
        let mut buf = self.main_segment_width as u64;
        buf = (buf << 16) | self.num_aux_segments as u64;
        if self.num_aux_segments == 1 {
            buf = (buf << 16) | self.aux_segment_widths[0] as u64;
            buf = (buf << 16) | self.aux_segment_rands[0] as u64;
        }
        result.push(E::from(buf));

        // parameters of all subsequent auxiliary segments go into additional elements
        for i in 1..self.num_aux_segments {
            buf = self.aux_segment_widths[i] as u64;
            buf = (buf << 16) | self.aux_segment_rands[i] as u64;
            result.push(E::from(buf));
        }

        result
    }
}

impl Serializable for TraceLayout {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(self.main_segment_width as u16);
        for &w in self.aux_segment_widths.iter() {
            debug_assert!(
                w <= u16::MAX as usize,
                "aux segment width does not fit into u8 value"
            );
            target.write_u16(w as u16);
        }
        for &rc in self.aux_segment_rands.iter() {
            debug_assert!(
                rc <= u8::MAX as usize,
                "aux segment random element count does not fit into u8 value"
            );
            target.write_u16(rc as u16);
        }
    }
}

impl Deserializable for TraceLayout {
    /// Reads [TraceLayout] from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid [TraceLayout] struct could not be read from the specified
    /// `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let main_width = source.read_u16()? as usize;
        if main_width == 0 {
            return Err(DeserializationError::InvalidValue(
                "main trace segment width must be greater than zero".to_string(),
            ));
        }

        // read and validate auxiliary trace segment widths
        let mut was_zero_width = false;
        let mut aux_widths = [0; NUM_AUX_SEGMENTS];
        for width in aux_widths.iter_mut() {
            *width = source.read_u16()? as usize;
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

        let full_trace_width = main_width + aux_widths.iter().sum::<usize>();
        if full_trace_width >= TraceInfo::MAX_TRACE_WIDTH {
            return Err(DeserializationError::InvalidValue(format!(
                "full trace width cannot be greater than {}, but was {}",
                TraceInfo::MAX_TRACE_WIDTH,
                full_trace_width
            )));
        }

        // read and validate number of random elements for each auxiliary trace segment
        let mut aux_rands = [0; NUM_AUX_SEGMENTS];
        for (num_rand_elements, &width) in aux_rands.iter_mut().zip(aux_widths.iter()) {
            *num_rand_elements = source.read_u16()? as usize;
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

        Ok(TraceLayout::new(main_width, aux_widths, aux_rands))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{ToElements, TraceLayout};
    use math::fields::f64::BaseElement;

    #[test]
    fn trace_layout_to_elements() {
        // --- test trace with only main segment ------------------------------
        let main_width: usize = 20;
        let num_aux_segments: usize = 0;

        let main_width_bytes = (main_width as u16).to_le_bytes();
        let num_aux_segments_bytes = (num_aux_segments as u16).to_le_bytes();
        let expected = u64::from_le_bytes([
            num_aux_segments_bytes[0],
            num_aux_segments_bytes[1],
            main_width_bytes[0],
            main_width_bytes[1],
            0,
            0,
            0,
            0,
        ]);
        let expected = vec![BaseElement::from(expected)];

        let layout = TraceLayout::new(main_width, [0], [0]);
        assert_eq!(expected, layout.to_elements());

        // --- test trace with one auxiliary segment --------------------------
        let main_width: usize = 20;
        let num_aux_segments: usize = 1;
        let aux_width: usize = 9;
        let aux_rands: usize = 12;

        let main_width_bytes = (main_width as u16).to_le_bytes();
        let num_aux_segments_bytes = (num_aux_segments as u16).to_le_bytes();
        let aux_width_bytes = (aux_width as u16).to_le_bytes();
        let aux_rands_bytes = (aux_rands as u16).to_le_bytes();
        let expected = u64::from_le_bytes([
            aux_rands_bytes[0],
            aux_rands_bytes[1],
            aux_width_bytes[0],
            aux_width_bytes[1],
            num_aux_segments_bytes[0],
            num_aux_segments_bytes[1],
            main_width_bytes[0],
            main_width_bytes[1],
        ]);
        let expected = vec![BaseElement::from(expected)];

        let layout = TraceLayout::new(main_width, [aux_width], [aux_rands]);
        assert_eq!(expected, layout.to_elements());
    }

    #[test]
    fn large_trace_layout_to_elements() {
        // --- test trace with only main segment ------------------------------
        let main_width: usize = 512;
        let num_aux_segments: usize = 0;

        let main_width_bytes = (main_width as u16).to_le_bytes();
        let num_aux_segments_bytes = (num_aux_segments as u16).to_le_bytes();
        let expected = u64::from_le_bytes([
            num_aux_segments_bytes[0],
            num_aux_segments_bytes[1],
            main_width_bytes[0],
            main_width_bytes[1],
            0,
            0,
            0,
            0,
        ]);
        let expected = vec![BaseElement::from(expected)];

        let layout = TraceLayout::new(main_width, [0], [0]);
        assert_eq!(expected, layout.to_elements());

        // --- test trace with one auxiliary segment --------------------------
        let main_width: usize = 1 << 15;
        let num_aux_segments: usize = 1;
        let aux_width: usize = 512;
        let aux_rands: usize = 12;

        let main_width_bytes = (main_width as u16).to_le_bytes();
        let num_aux_segments_bytes = (num_aux_segments as u16).to_le_bytes();
        let aux_width_bytes = (aux_width as u16).to_le_bytes();
        let aux_rands_bytes = (aux_rands as u16).to_le_bytes();
        let expected = u64::from_le_bytes([
            aux_rands_bytes[0],
            aux_rands_bytes[1],
            aux_width_bytes[0],
            aux_width_bytes[1],
            num_aux_segments_bytes[0],
            num_aux_segments_bytes[1],
            main_width_bytes[0],
            main_width_bytes[1],
        ]);
        let expected = vec![BaseElement::from(expected)];

        let layout = TraceLayout::new(main_width, [aux_width], [aux_rands]);
        assert_eq!(expected, layout.to_elements());
    }
}
