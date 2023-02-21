// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Deserializable, DeserializationError, Vec};

// BYTE READER TRAIT
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
pub trait ByteReader {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a single byte read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn read_u8(&mut self) -> Result<u8, DeserializationError>;

    /// Returns the next byte to be read from `self` without advancing the reader to the next byte.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn peek_u8(&self) -> Result<u8, DeserializationError>;

    /// Returns a byte vector of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a vector of the specified length could not be read
    /// from `self`.
    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError>;

    /// Returns a byte array of length `N` read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if an array of the specified length could not be read
    /// from `self`.
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError>;

    /// Checks if it is possible to read at least `num_bytes` bytes from this ByteReader
    ///
    /// # Errors
    /// Returns an error if, when reading the requested number of bytes, we go beyond the
    /// boundaries of the array
    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError>;

    /// Returns true if there are more bytes left to be read from `self`.
    fn has_more_bytes(&self) -> bool;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a boolean value read from `self` consuming 1 byte from the reader.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_bool(&mut self) -> Result<bool, DeserializationError> {
        let byte = self.read_u8()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DeserializationError::InvalidValue(format!(
                "{byte} is not a boolean value"
            ))),
        }
    }

    /// Returns a u16 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_u16(&mut self) -> Result<u16, DeserializationError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Returns a u32 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u32 value could not be read from `self`.
    fn read_u32(&mut self) -> Result<u32, DeserializationError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Returns a u64 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u64 value could not be read from `self`.
    fn read_u64(&mut self) -> Result<u64, DeserializationError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Returns a u128 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u128 value could not be read from `self`.
    fn read_u128(&mut self) -> Result<u128, DeserializationError> {
        let bytes = self.read_array::<16>()?;
        Ok(u128::from_le_bytes(bytes))
    }

    /// Reads a deserializable value from `self`.
    ///
    /// # Panics
    /// Panics if the value could not be read from `self`.
    fn read<D>(&mut self) -> Result<D, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        D::read_from(self)
    }
}

// SLICE READER
// ================================================================================================

/// Implements [ByteReader] trait for a slice of bytes.
pub struct SliceReader<'a> {
    source: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    /// Creates a new slice reader from the specified slice.
    pub fn new(source: &'a [u8]) -> Self {
        SliceReader { source, pos: 0 }
    }
}

impl<'a> ByteReader for SliceReader<'a> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        let result = self.source[self.pos];
        self.pos += 1;
        Ok(result)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.check_eor(1)?;
        Ok(self.source[self.pos])
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError> {
        self.check_eor(len)?;
        let result = self.source[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(result)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        self.check_eor(N)?;
        let mut result = [0_u8; N];
        result.copy_from_slice(&self.source[self.pos..self.pos + N]);
        self.pos += N;
        Ok(result)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        if self.pos + num_bytes > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        Ok(())
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }
}
