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

impl<T1> Serializable for (T1,)
where
    T1: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl<T1, T2> Serializable for (T1, T2)
where
    T1: Serializable,
    T2: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
    }
}

impl<T1, T2, T3> Serializable for (T1, T2, T3)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
    }
}

impl<T1, T2, T3, T4> Serializable for (T1, T2, T3, T4)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
    T4: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
        self.3.write_into(target);
    }
}

impl<T1, T2, T3, T4, T5> Serializable for (T1, T2, T3, T4, T5)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
    T4: Serializable,
    T5: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
        self.3.write_into(target);
        self.4.write_into(target);
    }
}

impl<T1, T2, T3, T4, T5, T6> Serializable for (T1, T2, T3, T4, T5, T6)
where
    T1: Serializable,
    T2: Serializable,
    T3: Serializable,
    T4: Serializable,
    T5: Serializable,
    T6: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
        self.1.write_into(target);
        self.2.write_into(target);
        self.3.write_into(target);
        self.4.write_into(target);
        self.5.write_into(target);
    }
}

impl Serializable for u8 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self);
    }
}

impl Serializable for u16 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(*self);
    }
}

impl Serializable for u32 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(*self);
    }
}

impl Serializable for u64 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(*self);
    }
}

impl<T: Serializable> Serializable for Option<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Some(v) => {
                target.write_bool(true);
                v.write_into(target);
            }
            None => target.write_bool(false),
        }
    }
}

impl<T: Serializable> Serializable for &Option<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Some(v) => {
                target.write_bool(true);
                v.write_into(target);
            }
            None => target.write_bool(false),
        }
    }
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

impl Serializable for String {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.len() as u64);
        target.write_bytes(self.as_bytes());
    }
}

impl Serializable for &String {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        (*self).write_into(target)
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

impl Deserializable for () {
    fn read_from<R: ByteReader>(_source: &mut R) -> Result<Self, DeserializationError> {
        Ok(())
    }
}

impl<T1> Deserializable for (T1,)
where
    T1: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        Ok((v1,))
    }
}

impl<T1, T2> Deserializable for (T1, T2)
where
    T1: Deserializable,
    T2: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        Ok((v1, v2))
    }
}

impl<T1, T2, T3> Deserializable for (T1, T2, T3)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        Ok((v1, v2, v3))
    }
}

impl<T1, T2, T3, T4> Deserializable for (T1, T2, T3, T4)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
    T4: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        let v4 = T4::read_from(source)?;
        Ok((v1, v2, v3, v4))
    }
}

impl<T1, T2, T3, T4, T5> Deserializable for (T1, T2, T3, T4, T5)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
    T4: Deserializable,
    T5: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        let v4 = T4::read_from(source)?;
        let v5 = T5::read_from(source)?;
        Ok((v1, v2, v3, v4, v5))
    }
}

impl<T1, T2, T3, T4, T5, T6> Deserializable for (T1, T2, T3, T4, T5, T6)
where
    T1: Deserializable,
    T2: Deserializable,
    T3: Deserializable,
    T4: Deserializable,
    T5: Deserializable,
    T6: Deserializable,
{
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = T1::read_from(source)?;
        let v2 = T2::read_from(source)?;
        let v3 = T3::read_from(source)?;
        let v4 = T4::read_from(source)?;
        let v5 = T5::read_from(source)?;
        let v6 = T6::read_from(source)?;
        Ok((v1, v2, v3, v4, v5, v6))
    }
}

impl Deserializable for u8 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u8()
    }
}

impl Deserializable for u16 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u16()
    }
}

impl Deserializable for u32 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u32()
    }
}

impl Deserializable for u64 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u64()
    }
}

impl<T: Deserializable> Deserializable for Option<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let contains = source.read_bool()?;

        match contains {
            true => Ok(Some(T::read_from(source)?)),
            false => Ok(None),
        }
    }
}

impl Deserializable for String {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let length = source
            .read_u64()?
            .try_into()
            .map_err(|err| DeserializationError::InvalidValue(format!("{err}",)))?;
        let data = source.read_vec(length)?;

        String::from_utf8(data).map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }
}
