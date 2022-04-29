// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! This crate contains utility traits, functions, and macros used by other crates of Winterfell
//! STARK prover and verifier.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

use core::{convert::TryInto, mem, slice};

pub mod collections;
use collections::Vec;

pub mod string;
use string::ToString;

pub mod iterators;

mod errors;
pub use errors::DeserializationError;

#[cfg(test)]
mod tests;

#[cfg(feature = "concurrent")]
use iterators::*;

#[cfg(feature = "concurrent")]
pub use rayon;

// SERIALIZABLE
// ================================================================================================

/// Defines how to serialize `Self` into bytes.
pub trait Serializable: Sized {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------
    /// Serializes `self` into bytes and writes these bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Serializes `self` into a vector of bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.get_size_hint());
        self.write_into(&mut result);
        result
    }

    /// Serializes all elements of the `source` and writes these bytes into the `target`.
    ///
    /// This method does not write any metadata (e.g. number of serialized elements) into the
    /// `target`.
    fn write_batch_into<W: ByteWriter>(source: &[Self], target: &mut W) {
        for item in source {
            item.write_into(target);
        }
    }

    /// Returns an estimate of how many bytes are needed to represent self.
    ///
    /// The default implementation returns zero.
    fn get_size_hint(&self) -> usize {
        0
    }
}

impl Serializable for () {
    fn write_into<W: ByteWriter>(&self, _target: &mut W) {}
}

impl<T: Serializable> Serializable for Vec<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        T::write_batch_into(self, target);
    }
}

impl<T: Serializable> Serializable for &Vec<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        T::write_batch_into(self, target);
    }
}

impl<T: Serializable, const N: usize> Serializable for Vec<[T; N]> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let source = flatten_slice_elements(self);
        T::write_batch_into(source, target);
    }
}

impl<T: Serializable, const N: usize> Serializable for &Vec<[T; N]> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let source = flatten_slice_elements(self);
        T::write_batch_into(source, target);
    }
}

impl<T: Serializable> Serializable for &[T] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        T::write_batch_into(self, target);
    }
}

impl<T: Serializable, const N: usize> Serializable for &[[T; N]] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let source = flatten_slice_elements(self);
        T::write_batch_into(source, target);
    }
}

// DESERIALIZABLE
// ================================================================================================

/// Defines how to deserialize `Self` from bytes.
pub trait Deserializable: Sized {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Reads a sequence of bytes from the provided `source`, attempts to deserialize these bytes
    /// into `Self`, and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The `source` does not contain enough bytes to deserialize `Self`.
    /// * Bytes read from the `source` do not represent a valid value for `Self`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Reads a sequence of bytes from the provided `source`, attempts to deserialize these bytes
    /// into a vector with the specified number of `Self` elements, and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The `source` does not contain enough bytes to deserialize the specified number of
    ///   elements.
    /// * Bytes read from the `source` do not represent a valid value for `Self` for any of the
    ///   elements.
    ///
    /// Note: if the error occurs, the reader is not rolled back to the state prior to calling
    /// this function.
    fn read_batch_from<R: ByteReader>(
        source: &mut R,
        num_elements: usize,
    ) -> Result<Vec<Self>, DeserializationError> {
        let mut result = Vec::new();
        for _ in 0..num_elements {
            let element = Self::read_from(source)?;
            result.push(element)
        }
        Ok(result)
    }
}

// BYTE READER
// ================================================================================================

/// Defines how primitive values are to be read from `Self`.
pub trait ByteReader {
    /// Returns a single byte read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] error the reader is at EOF.
    fn read_u8(&mut self) -> Result<u8, DeserializationError>;

    /// Returns a u16 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u16 value could not be read from `self`.
    fn read_u16(&mut self) -> Result<u16, DeserializationError>;

    /// Returns a u32 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u32 value could not be read from `self`.
    fn read_u32(&mut self) -> Result<u32, DeserializationError>;

    /// Returns a u64 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u64 value could not be read from `self`.
    fn read_u64(&mut self) -> Result<u64, DeserializationError>;

    /// Returns a u128 value read from `self` in little-endian byte order.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a u128 value could not be read from `self`.
    fn read_u128(&mut self) -> Result<u128, DeserializationError>;

    /// Returns a byte vector of the specified length read from `self`.
    ///
    /// # Errors
    /// Returns a [DeserializationError] if a vector of the specified length could not be read
    /// from `self`.
    fn read_u8_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError>;

    /// Returns a byte array of length `N` reade from `self`.
    fn read_u8_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError>;

    /// Returns true if there are more bytes left to be read from `self`.
    fn has_more_bytes(&self) -> bool;
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
        if self.pos >= self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self.source[self.pos];

        self.pos += 1;
        Ok(result)
    }

    fn read_u16(&mut self) -> Result<u16, DeserializationError> {
        let end_pos = self.pos + 2;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u16::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u32(&mut self) -> Result<u32, DeserializationError> {
        let end_pos = self.pos + 4;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u32::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u64(&mut self) -> Result<u64, DeserializationError> {
        let end_pos = self.pos + 8;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u64::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u128(&mut self) -> Result<u128, DeserializationError> {
        let end_pos = self.pos + 16;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let result = u128::from_le_bytes(
            self.source[self.pos..end_pos]
                .try_into()
                .map_err(|err| DeserializationError::UnknownError(format!("{}", err)))?,
        );

        self.pos = end_pos;
        Ok(result)
    }

    fn read_u8_vec(&mut self, len: usize) -> Result<Vec<u8>, DeserializationError> {
        let end_pos = self.pos + len as usize;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self.source[self.pos..end_pos].to_vec();
        self.pos = end_pos;
        Ok(result)
    }

    fn read_u8_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let end_pos = self.pos + N;
        if end_pos > self.source.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let result = self.source[self.pos..end_pos].try_into().map_err(|_| {
            DeserializationError::UnknownError("failed to convert slide into an array".to_string())
        })?;
        self.pos = end_pos;
        Ok(result)
    }

    fn has_more_bytes(&self) -> bool {
        self.pos < self.source.len()
    }
}

// BYTE WRITER
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
    fn write_u8_slice(&mut self, values: &[u8]);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Writes a u16 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u16(&mut self, value: u16) {
        self.write_u8_slice(&value.to_le_bytes());
    }

    /// Writes a u32 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u32(&mut self, value: u32) {
        self.write_u8_slice(&value.to_le_bytes());
    }

    /// Writes a u64 value in little-endian byte order into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write_u64(&mut self, value: u64) {
        self.write_u8_slice(&value.to_le_bytes());
    }

    /// Writes a serializable value into `self`.
    ///
    /// # Panics
    /// Panics if the value could not be written into `self`.
    fn write<S: Serializable>(&mut self, value: S) {
        value.write_into(self)
    }
}

impl ByteWriter for Vec<u8> {
    fn write_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn write_u8_slice(&mut self, values: &[u8]) {
        self.extend_from_slice(values);
    }
}

// AS BYTES
// ================================================================================================

/// Defines a zero-copy representation of `Self` as a sequence of bytes.
pub trait AsBytes {
    /// Returns a byte representation of `self`.
    ///
    /// This method is intended to re-interpret the underlying memory as a sequence of bytes, and
    /// thus, should be zero-copy.
    fn as_bytes(&self) -> &[u8];
}

impl<const N: usize, const M: usize> AsBytes for [[u8; N]; M] {
    /// Flattens a two-dimensional array of bytes into a slice of bytes.
    fn as_bytes(&self) -> &[u8] {
        let p = self.as_ptr();
        let len = N * M;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> AsBytes for [[u8; N]] {
    /// Flattens a slice of byte arrays into a slice of bytes.
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
/// This is usually faster than requesting a vector with initialized memory and is useful when we
/// overwrite all contents of the vector immediately after memory allocation.
///
/// # Safety
/// Using values from the returned vector before initializing them will lead to undefined behavior.
#[allow(clippy::uninit_vec)]
pub unsafe fn uninit_vector<T>(length: usize) -> Vec<T> {
    let mut vector = Vec::with_capacity(length);
    vector.set_len(length);
    vector
}

// GROUPING / UN-GROUPING FUNCTIONS
// ================================================================================================

/// Transmutes a vector of `n` elements into a vector of `n` / `N` elements, each of which is
/// an array of `N` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Panics
/// Panics if `n` is not divisible by `N`.
///
/// # Example
/// ```
/// # use winter_utils::group_vector_elements;
/// let a = vec![0_u32, 1, 2, 3, 4, 5, 6, 7];
/// let b: Vec<[u32; 2]> = group_vector_elements(a);
///
/// assert_eq!(vec![[0, 1], [2, 3], [4, 5], [6, 7]], b);
/// ```
pub fn group_vector_elements<T, const N: usize>(source: Vec<T>) -> Vec<[T; N]> {
    assert_eq!(
        source.len() % N,
        0,
        "source length must be divisible by {}, but was {}",
        N,
        source.len()
    );
    let mut v = mem::ManuallyDrop::new(source);
    let p = v.as_mut_ptr();
    let len = v.len() / N;
    let cap = v.capacity() / N;
    unsafe { Vec::from_raw_parts(p as *mut [T; N], len, cap) }
}

/// Transmutes a slice of `n` elements into a slice of `n` / `N` elements, each of which is
/// an array of `N` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Panics
/// Panics if `n` is not divisible by `N`.
///
/// # Example
/// ```
/// # use winter_utils::group_slice_elements;
/// let a = [0_u32, 1, 2, 3, 4, 5, 6, 7];
/// let b: &[[u32; 2]] = group_slice_elements(&a);
///
/// assert_eq!(&[[0, 1], [2, 3], [4, 5], [6, 7]], b);
/// ```
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

/// Transmutes a slice of `n` arrays each of length `N`, into a slice of `N` * `n` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Example
/// ```
/// # use winter_utils::flatten_slice_elements;
/// let a = vec![[1, 2, 3, 4], [5, 6, 7, 8]];
///
/// let b = flatten_slice_elements(&a);
/// assert_eq!(&[1, 2, 3, 4, 5, 6, 7, 8], b);
/// ```
pub fn flatten_slice_elements<T, const N: usize>(source: &[[T; N]]) -> &[T] {
    let p = source.as_ptr();
    let len = source.len() * N;
    unsafe { slice::from_raw_parts(p as *const T, len) }
}

/// Transmutes a vector of `n` arrays each of length `N`, into a vector of `N` * `n` elements.
///
/// This function just re-interprets the underlying memory and is thus zero-copy.
/// # Example
/// ```
/// # use winter_utils::flatten_vector_elements;
/// let a = vec![[1, 2, 3, 4], [5, 6, 7, 8]];
///
/// let b = flatten_vector_elements(a);
/// assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 8], b);
/// ```
pub fn flatten_vector_elements<T, const N: usize>(source: Vec<[T; N]>) -> Vec<T> {
    let v = mem::ManuallyDrop::new(source);
    let p = v.as_ptr();
    let len = v.len() * N;
    let cap = v.capacity() * N;
    unsafe { Vec::from_raw_parts(p as *mut T, len, cap) }
}

// TRANSPOSING
// ================================================================================================

/// Transposes a slice of `n` elements into a matrix with `N` columns and `n`/`N` rows.
///
/// When `concurrent` feature is enabled, the slice will be transposed using multiple threads.
///
/// # Panics
/// Panics if `n` is not divisible by `N`.
///
/// # Example
/// ```
/// # use winter_utils::transpose_slice;
/// let a = [0_u32, 1, 2, 3, 4, 5, 6, 7];
/// let b: Vec<[u32; 2]> = transpose_slice(&a);
///
/// assert_eq!(vec![[0, 4], [1, 5], [2, 6], [3, 7]], b);
/// ```
pub fn transpose_slice<T: Copy + Send + Sync, const N: usize>(source: &[T]) -> Vec<[T; N]> {
    let row_count = source.len() / N;
    assert_eq!(
        row_count * N,
        source.len(),
        "source length must be divisible by {}, but was {}",
        N,
        source.len()
    );

    let mut result = unsafe { group_vector_elements(uninit_vector(row_count * N)) };
    iter_mut!(result, 1024)
        .enumerate()
        .for_each(|(i, element)| {
            for j in 0..N {
                element[j] = source[i + j * row_count]
            }
        });
    result
}

// RANDOMNESS
// ================================================================================================

/// Defines how `Self` can be read from a sequence of random bytes.
pub trait Randomizable: Sized {
    /// Size of `Self` in bytes.
    ///
    /// This is used to determine how many bytes should be passed to the
    /// [from_random_bytes()](Self::from_random_bytes) function.
    const VALUE_SIZE: usize;

    /// Returns `Self` if the set of bytes forms a valid value, otherwise returns None.
    fn from_random_bytes(source: &[u8]) -> Option<Self>;
}

impl Randomizable for u128 {
    const VALUE_SIZE: usize = 16;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u128::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u64 {
    const VALUE_SIZE: usize = 8;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u32 {
    const VALUE_SIZE: usize = 4;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u16 {
    const VALUE_SIZE: usize = 2;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        if let Ok(bytes) = source[..Self::VALUE_SIZE].try_into() {
            Some(u16::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

impl Randomizable for u8 {
    const VALUE_SIZE: usize = 1;

    fn from_random_bytes(source: &[u8]) -> Option<Self> {
        Some(source[0])
    }
}
