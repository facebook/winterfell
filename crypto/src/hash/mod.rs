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

mod rescue;
pub use rescue::Rp62_248;

// HASHER TRAITS
// ================================================================================================

/// Defines a cryptographic hash function.
///
/// This trait defined hash procedures for the following inputs:
/// * A sequence of bytes.
/// * Two digests - this is intended for use in Merkle tree constructions.
/// * A digests and a u64 value - this intended for use in PRNG or PoW contexts.
pub trait Hasher {
    /// Specifies a digest type returned by this hasher.
    type Digest: Debug
        + Default
        + Copy
        + Clone
        + Eq
        + PartialEq
        + Send
        + Sync
        + AsRef<[u8]> // TODO: ideally, this should be remove in favor of returning arrays
        + Serializable
        + Deserializable;

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

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
    ///
    /// For malleable field elements, the elements are normalized first, and the hash is computed
    /// from internal representations of the normalized elements.
    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>;
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

impl<const N: usize> Default for ByteDigest<N> {
    fn default() -> Self {
        ByteDigest([0; N])
    }
}

impl<const N: usize> AsRef<[u8]> for ByteDigest<N> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Serializable for ByteDigest<N> {
    fn write_into<W: utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.0);
    }
}

impl<const N: usize> Deserializable for ByteDigest<N> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(ByteDigest(source.read_u8_array()?))
    }
}
