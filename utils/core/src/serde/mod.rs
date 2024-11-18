// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use super::DeserializationError;

mod byte_reader;
#[cfg(feature = "std")]
pub use byte_reader::ReadAdapter;
pub use byte_reader::{ByteReader, SliceReader};

mod byte_writer;
pub use byte_writer::ByteWriter;

// SERIALIZABLE TRAIT
// ================================================================================================

/// Defines how to serialize `Self` into bytes.
pub trait Serializable {
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

    /// Returns an estimate of how many bytes are needed to represent self.
    ///
    /// The default implementation returns zero.
    fn get_size_hint(&self) -> usize {
        0
    }
}

impl<T: Serializable> Serializable for &T {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        (*self).write_into(target)
    }

    fn get_size_hint(&self) -> usize {
        (*self).get_size_hint()
    }
}

impl Serializable for () {
    fn write_into<W: ByteWriter>(&self, _target: &mut W) {}

    fn get_size_hint(&self) -> usize {
        0
    }
}

impl<T1> Serializable for (T1,)
where
    T1: Serializable,
{
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
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

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint() + self.1.get_size_hint()
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

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint() + self.1.get_size_hint() + self.2.get_size_hint()
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

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
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

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
            + self.4.get_size_hint()
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

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
            + self.1.get_size_hint()
            + self.2.get_size_hint()
            + self.3.get_size_hint()
            + self.4.get_size_hint()
            + self.5.get_size_hint()
    }
}

impl Serializable for u8 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u8>()
    }
}

impl Serializable for u16 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u16(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u16>()
    }
}

impl Serializable for u32 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u32>()
    }
}

impl Serializable for u64 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u64>()
    }
}

impl Serializable for u128 {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u128(*self);
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<u128>()
    }
}

impl Serializable for usize {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(*self)
    }

    fn get_size_hint(&self) -> usize {
        byte_writer::usize_encoded_len(*self as u64)
    }
}

impl<T: Serializable> Serializable for Option<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Some(v) => {
                target.write_bool(true);
                v.write_into(target);
            },
            None => target.write_bool(false),
        }
    }

    fn get_size_hint(&self) -> usize {
        core::mem::size_of::<bool>() + self.as_ref().map(|value| value.get_size_hint()).unwrap_or(0)
    }
}

impl<T: Serializable, const C: usize> Serializable for [T; C] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_many(self)
    }

    fn get_size_hint(&self) -> usize {
        let mut size = 0;
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl<T: Serializable> Serializable for [T] {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        for element in self.iter() {
            element.write_into(target);
        }
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for element in self {
            size += element.get_size_hint();
        }
        size
    }
}

impl<T: Serializable> Serializable for Vec<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self);
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl<K: Serializable, V: Serializable> Serializable for BTreeMap<K, V> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self);
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl<T: Serializable> Serializable for BTreeSet<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self);
    }

    fn get_size_hint(&self) -> usize {
        let mut size = self.len().get_size_hint();
        for item in self {
            size += item.get_size_hint();
        }
        size
    }
}

impl Serializable for str {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        self.len().get_size_hint() + self.len()
    }
}

impl Serializable for String {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_many(self.as_bytes());
    }

    fn get_size_hint(&self) -> usize {
        self.len().get_size_hint() + self.len()
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

impl Deserializable for u128 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u128()
    }
}

impl Deserializable for usize {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_usize()
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

impl<T: Deserializable, const C: usize> Deserializable for [T; C] {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let data: Vec<T> = source.read_many(C)?;

        // SAFETY: the call above only returns a Vec if there are `C` elements, this conversion
        // always succeeds
        let res = data.try_into().unwrap_or_else(|v: Vec<T>| {
            panic!("Expected a Vec of length {} but it was {}", C, v.len())
        });

        Ok(res)
    }
}

impl<T: Deserializable> Deserializable for Vec<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        source.read_many(len)
    }
}

impl<K: Deserializable + Ord, V: Deserializable> Deserializable for BTreeMap<K, V> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        let data = source.read_many(len)?;
        Ok(BTreeMap::from_iter(data))
    }
}

impl<T: Deserializable + Ord> Deserializable for BTreeSet<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        let data = source.read_many(len)?;
        Ok(BTreeSet::from_iter(data))
    }
}

impl Deserializable for String {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let len = source.read_usize()?;
        let data = source.read_many(len)?;

        String::from_utf8(data)
            .map_err(|err| DeserializationError::InvalidValue(format!("{}", err)))
    }
}
