// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains utility traits, functions, and macros used by other crates of Winterfell
//! STARK prover and verifier.

use core::{convert::TryInto, mem, slice};

mod iterators;

mod errors;
pub use errors::DeserializationError;

#[cfg(test)]
mod tests;

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// SERIALIZABLE
// ================================================================================================

/// Defines how to serialize `Self` into bytes.
pub trait Serializable: Sized {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------
    /// Serializes `self` into bytes and appends the bytes at the end of the `target` vector.
    fn write_into(&self, target: &mut Vec<u8>);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Serializes `self` into a vector of bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.get_size_hint());
        self.write_into(&mut result);
        result
    }

    /// Serializes all elements of the `source` and appends the resulting bytes at the end of
    /// the `target` vector.
    ///
    /// This method does not write any metadata (e.g. number of serialized elements) into the
    /// `target`.
    fn write_batch_into(source: &[Self], target: &mut Vec<u8>) {
        for item in source {
            item.write_into(target);
        }
    }

    /// Serializes all individual elements contained in the `source` and appends the resulting
    /// bytes at the end of the `target` vector.
    ///
    /// This method does not write any metadata (e.g. number of serialized elements) into the
    /// `target`.
    fn write_array_batch_into<const N: usize>(source: &[[Self; N]], target: &mut Vec<u8>) {
        let source = flatten_slice_elements(source);
        Self::write_batch_into(source, target);
    }

    /// Returns an estimate of how many bytes are needed to represent self.
    ///
    /// The default implementation returns zero.
    fn get_size_hint(&self) -> usize {
        0
    }
}

impl Serializable for () {
    fn write_into(&self, _target: &mut Vec<u8>) {}
}

// BYTE READER
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
pub trait ByteReader {
    /// Returns a single byte read from `self` at the specified position.
    ///
    /// After the byte is read, `pos` is incremented by one.
    ///
    /// # Errors
    /// Returns a `DeserializationError` error if `pos` is out of bounds.
    fn read_u8(&self, pos: &mut usize) -> Result<u8, DeserializationError>;

    /// Returns a u16 value read from `self` in little-endian byte order starting at the specified
    /// position.
    ///
    /// After the value is read, `pos` is incremented by two.
    ///
    /// # Errors
    /// Returns an error if a u16 value could not be read.
    fn read_u16(&self, pos: &mut usize) -> Result<u16, DeserializationError>;

    /// Returns a u32 value read from `self` in little-endian byte order starting at the specified
    /// position.
    ///
    /// After the value is read, `pos` is incremented by four.
    ///
    /// # Errors
    /// Returns an error if a u32 value could not be read.
    fn read_u32(&self, pos: &mut usize) -> Result<u32, DeserializationError>;

    /// Returns a u64 value read from `self` in little-endian byte order starting at the specified
    /// position.
    ///
    /// After the value is read, `pos` is incremented by eight.
    ///
    /// # Errors
    /// Returns an error if a u64 value could not be read.
    fn read_u64(&self, pos: &mut usize) -> Result<u64, DeserializationError>;

    /// Returns a byte vector of the specified length read from `self` starting at the specified
    /// position.
    ///
    /// After the vector is read, `pos` is incremented by the length of the vector.
    ///
    /// # Errors
    /// Returns an error if a u16 value could not be read.
    fn read_u8_vec(&self, pos: &mut usize, len: usize) -> Result<Vec<u8>, DeserializationError>;
}

impl ByteReader for [u8] {
    fn read_u8(&self, pos: &mut usize) -> Result<u8, DeserializationError> {
        if *pos >= self.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self[*pos];

        *pos += 1;
        Ok(result)
    }

    fn read_u16(&self, pos: &mut usize) -> Result<u16, DeserializationError> {
        let end_pos = *pos + 2;
        if end_pos > self.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u16::from_le_bytes(
            self[*pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        *pos = end_pos;
        Ok(result)
    }

    fn read_u32(&self, pos: &mut usize) -> Result<u32, DeserializationError> {
        let end_pos = *pos + 4;
        if end_pos > self.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u32::from_le_bytes(
            self[*pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        *pos = end_pos;
        Ok(result)
    }

    fn read_u64(&self, pos: &mut usize) -> Result<u64, DeserializationError> {
        let end_pos = *pos + 8;
        if end_pos > self.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u64::from_le_bytes(
            self[*pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        *pos = end_pos;
        Ok(result)
    }

    fn read_u8_vec(&self, pos: &mut usize, len: usize) -> Result<Vec<u8>, DeserializationError> {
        let end_pos = *pos + len as usize;
        if end_pos > self.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self[*pos..end_pos].to_vec();
        *pos = end_pos;
        Ok(result)
    }
}

impl ByteReader for Vec<u8> {
    fn read_u8(&self, pos: &mut usize) -> Result<u8, DeserializationError> {
        self.as_slice().read_u8(pos)
    }

    fn read_u16(&self, pos: &mut usize) -> Result<u16, DeserializationError> {
        self.as_slice().read_u16(pos)
    }

    fn read_u32(&self, pos: &mut usize) -> Result<u32, DeserializationError> {
        self.as_slice().read_u32(pos)
    }

    fn read_u64(&self, pos: &mut usize) -> Result<u64, DeserializationError> {
        self.as_slice().read_u64(pos)
    }

    fn read_u8_vec(&self, pos: &mut usize, len: usize) -> Result<Vec<u8>, DeserializationError> {
        self.as_slice().read_u8_vec(pos, len)
    }
}

// BYTE WRITER
// ================================================================================================

/// Defines how primitive values are to be written into `Self`.
pub trait ByteWriter {
    fn write_u8(&mut self, value: u8);
    fn write_u16(&mut self, value: u16);
    fn write_u32(&mut self, value: u32);
    fn write_u8_slice(&mut self, values: &[u8]);
}

impl ByteWriter for Vec<u8> {
    fn write_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u8_slice(&mut self, values: &[u8]) {
        self.extend_from_slice(values);
    }
}

// AS BYTES
// ================================================================================================

/// Defines a zero-copy representation of `Self` as a sequence of bytes.
pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize, const M: usize> AsBytes for [[u8; N]; M] {
    /// Flattens an array of array of bytes into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = N * M;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> AsBytes for [[u8; N]] {
    /// Flattens a slice of array of bytes into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = self.len() * N;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

// VECTOR FUNCTIONS
// ================================================================================================

/// Returns a vector of the specified length with un-initialized memory.
///
/// This is faster than requesting a vector with initialized memory and is useful when we
/// overwrite all contents of the vector immediately after initialization. Otherwise, this will
/// lead to undefined behavior.
pub fn uninit_vector<T>(length: usize) -> Vec<T> {
    let mut vector = Vec::with_capacity(length);
    unsafe {
        vector.set_len(length);
    }
    vector
}

// GROUPING / UN-GROUPING FUNCTIONS
// ================================================================================================

/// Transmutes a vector of n elements into a vector of n / N elements, each of which is
/// an array of N elements.
///
/// Panics if n is not divisible by N.
pub fn group_vector_elements<T, const N: usize>(source: Vec<T>) -> Vec<[T; N]> {
    assert_eq!(
        source.len() % N,
        0,
        "source length must be divisible by {}",
        N
    );
    let mut v = mem::ManuallyDrop::new(source);
    let p = v.as_mut_ptr();
    let len = v.len() / N;
    let cap = v.capacity() / N;
    unsafe { Vec::from_raw_parts(p as *mut [T; N], len, cap) }
}

/// Transmutes a slice of n elements into a slice of n / N elements, each of which is
/// an array of N elements.
///
/// Panics if n is not divisible by N.
pub fn group_slice_elements<T, const N: usize>(source: &[T]) -> &[[T; N]] {
    assert_eq!(
        source.len() % N,
        0,
        "source length must be divisible by {}",
        N
    );
    let p = source.as_ptr();
    let len = source.len() / N;
    unsafe { slice::from_raw_parts(p as *const [T; N], len) }
}

/// Transmutes a slice of n arrays each of length N, into a slice of N * n elements.
pub fn flatten_slice_elements<T, const N: usize>(source: &[[T; N]]) -> &[T] {
    let p = source.as_ptr();
    let len = source.len() * N;
    unsafe { slice::from_raw_parts(p as *const T, len) }
}

/// Transmutes a vector of n arrays each of length N, into a vector of N * n elements.
pub fn flatten_vector_elements<T, const N: usize>(source: Vec<[T; N]>) -> Vec<T> {
    let v = mem::ManuallyDrop::new(source);
    let p = v.as_ptr();
    let len = v.len() * N;
    let cap = v.capacity() * N;
    unsafe { Vec::from_raw_parts(p as *mut T, len, cap) }
}

// TRANSPOSING
// ================================================================================================

/// Transposes a slice of n elements into a matrix with N columns and n/N rows.
pub fn transpose_slice<T: Copy + Send + Sync, const N: usize>(source: &[T]) -> Vec<[T; N]> {
    let row_count = source.len() / N;

    let mut result = group_vector_elements(uninit_vector(row_count * N));
    iter_mut!(result, 1024)
        .enumerate()
        .for_each(|(i, element)| {
            for j in 0..N {
                element[j] = source[i + j * row_count]
            }
        });
    result
}
