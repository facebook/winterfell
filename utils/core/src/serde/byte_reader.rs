// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{Deserializable, DeserializationError};
use crate::collections::*;
use crate::string::*;

// BYTE READER TRAIT
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
///
/// Whenever data is read from the reader using any of the `read_*` functions, the reader advances
/// to the next unread byte. If the error occurs, the reader is not rolled back to the state prior
/// to calling any of the function.
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

    /// Returns a slice of bytes of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a slice of the specified length could not be read
    /// from `self`.
    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError>;

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
    /// the data available in the reader.
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
            _ => Err(DeserializationError::InvalidValue(format!("{byte} is not a boolean value"))),
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

    /// Returns a usize value read from `self` in [vint64](https://docs.rs/vint64/latest/vint64/)
    /// format.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if:
    /// * usize value could not be read from `self`.
    /// * encoded value is greater than `usize` maximum value on a given platform.
    fn read_usize(&mut self) -> Result<usize, DeserializationError> {
        let first_byte = self.peek_u8()?;
        let length = first_byte.trailing_zeros() as usize + 1;

        let result = if length == 9 {
            // 9-byte special case
            self.read_u8()?;
            let value = self.read_array::<8>()?;
            u64::from_le_bytes(value)
        } else {
            let mut encoded = [0u8; 8];
            let value = self.read_slice(length)?;
            encoded[..length].copy_from_slice(value);
            u64::from_le_bytes(encoded) >> length
        };

        // check if the result value is within acceptable bounds for `usize` on a given platform
        if result > usize::MAX as u64 {
            return Err(DeserializationError::InvalidValue(format!(
                "Encoded value must be less than {}, but {} was provided",
                usize::MAX,
                result
            )));
        }

        Ok(result as usize)
    }

    /// Returns a byte vector of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a vector of the specified length could not be read
    /// from `self`.
    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError> {
        let data = self.read_slice(len)?;
        Ok(data.to_vec())
    }

    /// Returns a String of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a String of the specified length could not be read
    /// from `self`.
    fn read_string(&mut self, num_bytes: usize) -> Result<String, DeserializationError> {
        let data = self.read_vec(num_bytes)?;
        String::from_utf8(data).map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }

    /// Reads a deserializable value from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if the specified value could not be read from `self`.
    fn read<D>(&mut self) -> Result<D, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        D::read_from(self)
    }

    /// Reads a sequence of bytes from `self`, attempts to deserialize these bytes into a vector
    /// with the specified number of `D` elements, and returns the result.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if the specified number elements could not be read from
    /// `self`.
    fn read_many<D>(&mut self, num_elements: usize) -> Result<Vec<D>, DeserializationError>
    where
        Self: Sized,
        D: Deserializable,
    {
        let mut result = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            let element = D::read_from(self)?;
            result.push(element)
        }
        Ok(result)
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

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        self.check_eor(len)?;
        let result = &self.source[self.pos..self.pos + len];
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
