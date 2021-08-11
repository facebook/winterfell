// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{convert::TryInto, fmt::Debug, marker::PhantomData, slice};
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
    ///
    /// For malleable field elements, the elements are normalized first, and the hash is computed
    /// from internal representations of the normalized elements.
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
    type Digest = ByteDigest<32>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        ByteDigest(*blake3::hash(bytes).as_bytes())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ByteDigest(blake3::hash(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        ByteDigest(*blake3::hash(&data).as_bytes())
    }
}

impl<B: StarkField> ElementHasher for Blake3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_MALLEABLE {
            // when elements are malleable, normalize their internal representation before hashing
            let mut hasher = blake3::Hasher::new();
            for element in elements.iter() {
                let mut element = *element;
                element.normalize();
                hasher.update(element.as_bytes());
            }
            ByteDigest(*hasher.finalize().as_bytes())
        } else {
            // for non-malleable elements, hash them as is (in their internal representation)
            let bytes = E::elements_as_bytes(elements);
            ByteDigest(*blake3::hash(bytes).as_bytes())
        }
    }
}

/// Implementation of the [Hasher](super::Hasher) trait for BLAKE3 hash function with 192-bit
/// output.
#[derive(Debug, PartialEq, Eq)]
pub struct Blake3_192<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Blake3_192<B> {
    type Digest = ByteDigest<24>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let result = blake3::hash(bytes);
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let result = blake3::hash(ByteDigest::digests_as_bytes(values));
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 32];
        data[..24].copy_from_slice(&seed.0);
        data[24..].copy_from_slice(&value.to_le_bytes());

        let result = blake3::hash(&data);
        ByteDigest(result.as_bytes()[..24].try_into().unwrap())
    }
}

impl<B: StarkField> ElementHasher for Blake3_192<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_MALLEABLE {
            // when elements are malleable, normalize their internal representation before hashing
            let mut hasher = blake3::Hasher::new();
            for element in elements.iter() {
                let mut element = *element;
                element.normalize();
                hasher.update(element.as_bytes());
            }
            let result = hasher.finalize();
            ByteDigest(result.as_bytes()[..24].try_into().unwrap())
        } else {
            // for non-malleable elements, hash them as is (in their internal representation)
            let bytes = E::elements_as_bytes(elements);
            let result = blake3::hash(bytes);
            ByteDigest(result.as_bytes()[..24].try_into().unwrap())
        }
    }
}

// SHA3
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for SHA3 hash function with 256-bit
/// output.
pub struct Sha3_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha3_256<B> {
    type Digest = ByteDigest<32>;

    fn hash(bytes: &[u8]) -> Self::Digest {
        ByteDigest(sha3::Sha3_256::digest(bytes).into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ByteDigest(sha3::Sha3_256::digest(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        ByteDigest(sha3::Sha3_256::digest(&data).into())
    }
}

impl<B: StarkField> ElementHasher for Sha3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_MALLEABLE {
            // when elements are malleable, normalize their internal representation before hashing
            let mut hasher = sha3::Sha3_256::new();
            for element in elements.iter() {
                let mut element = *element;
                element.normalize();
                hasher.update(element.as_bytes());
            }
            ByteDigest(hasher.finalize().into())
        } else {
            // for non-malleable elements, hash them as is (in their internal representation)
            let bytes = E::elements_as_bytes(elements);
            ByteDigest(sha3::Sha3_256::digest(bytes).into())
        }
    }
}

// DIGESTS
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ByteDigest<const N: usize>([u8; N]);

impl<const N: usize> ByteDigest<N> {
    pub fn new(value: [u8; N]) -> Self {
        Self(value)
    }

    #[inline(always)]
    pub fn bytes_to_digests(bytes: &[[u8; N]]) -> &[ByteDigest<N>] {
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
