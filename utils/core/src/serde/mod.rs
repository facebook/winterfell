// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{flatten_slice_elements, DeserializationError, Vec};

mod byte_reader;
pub use byte_reader::{ByteReader, SliceReader};

mod byte_writer;
pub use byte_writer::ByteWriter;

// SERIALIZABLE TRAIT
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

    /// Attempts to deserialize the provided `bytes` into `Self` and returns the result.
    ///
    /// # Errors
    /// Returns an error if:
    /// * The `bytes` do not contain enough information to deserialize `Self`.
    /// * The `bytes` do not represent a valid value for `Self`.
    ///
    /// Note: if `bytes` contains more data than needed to deserialize `self`, no error is
    /// returned.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from(&mut SliceReader::new(bytes))
    }

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
        let mut result = Vec::with_capacity(num_elements);
        for _ in 0..num_elements {
            let element = Self::read_from(source)?;
            result.push(element)
        }
        Ok(result)
    }
}
