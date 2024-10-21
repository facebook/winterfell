// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{fmt::Debug, slice};

use math::{FieldElement, StarkField};
use utils::{ByteReader, Deserializable, DeserializationError, Serializable};

mod blake;
pub use blake::{Blake3_192, Blake3_256};

mod sha;
pub use sha::Sha3_256;

mod mds;

mod rescue;
pub use rescue::{Rp62_248, Rp64_256, RpJive64_256};

// HASHER TRAITS
// ================================================================================================

/// Defines a cryptographic hash function.
///
/// This trait defines hash procedures for the following inputs:
/// * A sequence of bytes.
/// * Two digests - this is intended for use in Merkle tree constructions.
/// * A digests and a u64 value - this intended for use in PRNG or PoW contexts.
pub trait Hasher {
    /// Specifies a digest type returned by this hasher.
    type Digest: Digest;

    /// Collision resistance of the hash function measured in bits.
    const COLLISION_RESISTANCE: u32;

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    /// Returns a hash of many digests.
    fn merge_many(values: &[Self::Digest]) -> Self::Digest;

    /// Returns hash(`seed` || `value`). This method is intended for use in PRNG and PoW contexts.
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest;
}

/// Defines a cryptographic hash function for hashing field elements.
///
/// This trait defines a hash procedure for a sequence of field elements. The elements can be
/// either in the base field specified for this hasher, or in an extension of the base field.
pub trait ElementHasher: Hasher {
    /// Specifies a base field for elements which can be hashed with this hasher.
    type BaseField: StarkField;

    /// Returns a hash of the provided field elements.
    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>;
}

// DIGEST TRAIT
// ================================================================================================

/// Defines output type for a cryptographic hash function.
pub trait Digest:
    Debug + Default + Copy + Clone + Eq + PartialEq + Send + Sync + Serializable + Deserializable
{
    /// Returns this digest serialized into an array of bytes.
    ///
    /// Ideally, the length of the returned array should be defined by an associated constant, but
    /// using associated constants in const generics is not supported by Rust yet. Thus, we put an
    /// upper limit on the possible digest size. For digests which are smaller than 32 bytes, the
    /// unused bytes should be set to 0.
    fn as_bytes(&self) -> [u8; 32];
}

// BYTE DIGEST
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ByteDigest<const N: usize>([u8; N]);

impl<const N: usize> ByteDigest<N> {
    pub fn new(value: [u8; N]) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn bytes_as_digests(bytes: &[[u8; N]]) -> &[ByteDigest<N>] {
        let p = bytes.as_ptr();
        let len = bytes.len();
        unsafe { slice::from_raw_parts(p as *const ByteDigest<N>, len) }
    }

    #[inline(always)]
    pub fn digests_as_bytes(digests: &[ByteDigest<N>]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * N;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl<const N: usize> Digest for ByteDigest<N> {
    fn as_bytes(&self) -> [u8; 32] {
        let mut result = [0; 32];
        result[..N].copy_from_slice(&self.0);
        result
    }
}

impl<const N: usize> Default for ByteDigest<N> {
    fn default() -> Self {
        ByteDigest([0; N])
    }
}

impl<const N: usize> Serializable for ByteDigest<N> {
    fn write_into<W: utils::ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl<const N: usize> Deserializable for ByteDigest<N> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ByteDigest(source.read_array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteDigest, Digest};

    #[test]
    fn byte_digest_as_bytes() {
        let d = ByteDigest::new([255_u8; 32]);
        assert_eq!([255_u8; 32], d.as_bytes());

        let d = ByteDigest::new([255_u8; 31]);
        let mut expected = [255_u8; 32];
        expected[31] = 0;
        assert_eq!(expected, d.as_bytes());
    }
}
