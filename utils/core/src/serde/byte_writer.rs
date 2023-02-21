// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Serializable, Vec};

// BYTE WRITER TRAIT
// ================================================================================================

/// Defines how primitive values are to be written into `Self`.
pub trait ByteWriter: Sized {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Writes a single byte into `self`.
    ///
    /// # Panics
    /// Panics if the byte could not be written into `self`.
    fn write_u8(&mut self, value: u8);

    /// Writes a sequence of bytes into `self`.
    ///
    /// # Panics
    /// Panics if the sequence of bytes could not be written into `self`.
    fn write_bytes(&mut self, values: &[u8]);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Writes a boolean value into `self`.
    ///
    /// A boolean value is written as a single byte.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_bool(&mut self, val: bool) {
        self.write_u8(val as u8);
    }

    /// Writes a u16 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a u32 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u32(&mut self, value: u32) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a u64 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a serializable value into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write<S: Serializable>(&mut self, value: S) {
        value.write_into(self)
    }
}

// BYTE WRITER IMPLEMENTATIONS
// ================================================================================================

impl ByteWriter for Vec<u8> {
    fn write_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn write_bytes(&mut self, values: &[u8]) {
        self.extend_from_slice(values);
    }
}
