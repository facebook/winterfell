// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use utils::collections::Vec;

// TRACE INFO
// ================================================================================================
/// Information about a specific execution trace.
///
/// Trace info consists of trace width, length, and optional custom metadata. Metadata is just a
/// vector of bytes and can store any values up to 64KB in size.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TraceInfo {
    width: usize,
    length: usize,
    meta: Vec<u8>,
}

impl TraceInfo {
    /// Smallest allowed execution trace length; currently set at 8.
    pub const MIN_TRACE_LENGTH: usize = 8;
    /// Maximum number of registers in an execution trace; currently set at 255.
    pub const MAX_TRACE_WIDTH: usize = 255;
    /// Maximum number of bytes in trace metadata; currently set at 65535.
    pub const MAX_META_LENGTH: usize = 65535;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new trace info from the specified length.
    ///
    /// # Panics
    /// Panics if:
    /// * `width` is zero or greater than 255.
    /// * `length` is smaller than 8 or is not a power of two.
    pub fn new(width: usize, length: usize) -> Self {
        Self::with_meta(width, length, vec![])
    }

    /// Creates a new trace info from the specified length and metadata.
    ///
    /// # Panics
    /// Panics if:
    /// * `width` is zero or greater than 255.
    /// * `length` is smaller than 8 or is not a power of two.
    /// * Length of `meta` is greater than 65535;
    pub fn with_meta(width: usize, length: usize, meta: Vec<u8>) -> Self {
        assert!(width > 0, "trace width must be greater than 0");
        assert!(
            width <= Self::MAX_TRACE_WIDTH,
            "trace width cannot be greater than {}, but was {}",
            Self::MAX_TRACE_WIDTH,
            width
        );
        assert!(
            length >= Self::MIN_TRACE_LENGTH,
            "trace length must be at least {}, but was {}",
            Self::MIN_TRACE_LENGTH,
            length
        );
        assert!(
            length.is_power_of_two(),
            "trace length must be a power of two, but was {}",
            length
        );
        assert!(
            meta.len() <= Self::MAX_META_LENGTH,
            "number of metadata bytes cannot be greater than {}, but was {}",
            Self::MAX_META_LENGTH,
            meta.len()
        );
        TraceInfo {
            width,
            length,
            meta,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns execution trace width;
    ///
    /// This is guaranteed to be between 1 and 255.
    pub fn width(&self) -> usize {
        self.width
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
}
