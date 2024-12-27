// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::Serializable;

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

    /// Writes a u128 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u128(&mut self, value: u128) {
        self.write_bytes(&value.to_le_bytes());
    }

    /// Writes a usize value in [vint64](https://docs.rs/vint64/latest/vint64/) format into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_usize(&mut self, value: usize) {
        // convert the value into a u64 so that we always get 8 bytes from to_le_bytes() call
        let value = value as u64;
        let length = usize_encoded_len(value);

        // 9-byte special case
        if length == 9 {
            // length byte is zero in this case
            self.write_u8(0);
            self.write(value.to_le_bytes());
        } else {
            let encoded_bytes = (((value << 1) | 1) << (length - 1)).to_le_bytes();
            self.write_bytes(&encoded_bytes[..length]);
        }
    }

    /// Writes a serializable value into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write<S: Serializable>(&mut self, value: S) {
        value.write_into(self)
    }

    /// Serializes all `elements` and writes the resulting bytes into `self`.
    ///
    /// This method does not write any metadata (e.g. number of serialized elements) into `self`.
    fn write_many<S, T>(&mut self, elements: T)
    where
        T: IntoIterator<Item = S>,
        S: Serializable,
    {
        for element in elements {
            element.write_into(self);
        }
    }
}

// BYTE WRITER IMPLEMENTATIONS
// ================================================================================================

#[cfg(feature = "std")]
impl<W: std::io::Write> ByteWriter for W {
    #[inline(always)]
    fn write_u8(&mut self, byte: u8) {
        <W as std::io::Write>::write_all(self, &[byte]).expect("write failed")
    }
    #[inline(always)]
    fn write_bytes(&mut self, bytes: &[u8]) {
        <W as std::io::Write>::write_all(self, bytes).expect("write failed")
    }
}

#[cfg(not(feature = "std"))]
impl ByteWriter for alloc::vec::Vec<u8> {
    fn write_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn write_bytes(&mut self, values: &[u8]) {
        self.extend_from_slice(values);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the length of the usize value in vint64 encoding.
pub(super) fn usize_encoded_len(value: u64) -> usize {
    let zeros = value.leading_zeros() as usize;
    let len = zeros.saturating_sub(1) / 7;
    9 - core::cmp::min(len, 8)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn write_adapter_passthrough() {
        let mut writer = Cursor::new([0u8; 128]);
        writer.write_bytes(b"nope");
        let buf = writer.get_ref();
        assert_eq!(&buf[..4], b"nope");
    }

    #[test]
    #[should_panic]
    fn write_adapter_writer_out_of_capacity() {
        let mut writer = Cursor::new([0; 2]);
        writer.write_bytes(b"nope");
    }
}
