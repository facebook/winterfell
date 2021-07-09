// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{fmt::Debug, marker::PhantomData, slice};
use math::{FieldElement, StarkField};
use sha3::Digest;
use utils::{ByteReader, Deserializable, DeserializationError, Serializable};

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
    fn hash_elements<E>(elements: &[E]) -> Self::Digest
    where
        E: FieldElement<BaseField = Self::BaseField>;
}

// BLAKE3
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for BLAKE3 hash function with 256-bit
/// output.
#[derive(Debug, PartialEq, Eq)]
pub struct Blake3_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Blake3_256<B> {
    type Digest = Digest256;

    fn hash(bytes: &[u8]) -> Self::Digest {
        Digest256(blake3::hash(bytes).into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Digest256(blake3::hash(Digest256::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        Digest256(blake3::hash(&data).into())
    }
}

impl<B: StarkField> ElementHasher for Blake3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        Digest256(blake3::hash(bytes).into())
    }
}

// SHA3
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for SHA3 hash function with 256-bit
/// output.
pub struct Sha3_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha3_256<B> {
    type Digest = Digest256;

    fn hash(bytes: &[u8]) -> Self::Digest {
        Digest256(sha3::Sha3_256::digest(bytes).into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        Digest256(sha3::Sha3_256::digest(Digest256::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        Digest256(sha3::Sha3_256::digest(&data).into())
    }
}

impl<B: StarkField> ElementHasher for Sha3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        Digest256(sha3::Sha3_256::digest(bytes).into())
    }
}

// DIGESTS
// ================================================================================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub struct Digest256([u8; 32]);

impl Digest256 {
    pub fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn bytes_to_digests(bytes: &[[u8; 32]]) -> &[Digest256] {
        let p = bytes.as_ptr();
        let len = bytes.len();
        unsafe { slice::from_raw_parts(p as *const Digest256, len) }
    }

    #[inline(always)]
    pub fn digests_as_bytes(digests: &[Digest256]) -> &[u8] {
        let p = digests.as_ptr();
        let len = digests.len() * 32;
        unsafe { slice::from_raw_parts(p as *const u8, len) }
    }
}

impl AsRef<[u8]> for Digest256 {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serializable for Digest256 {
    fn write_into<W: utils::ByteWriter>(&self, target: &mut W) {
        target.write_u8_slice(&self.0);
    }
}

impl Deserializable for Digest256 {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Digest256(source.read_u8_array()?))
    }
}
