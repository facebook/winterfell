// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{fmt::Debug, marker::PhantomData};
use math::{FieldElement, StarkField};
use sha3::Digest;
use utils::{AsBytes, ByteReader, DeserializationError};

// HASHER TRAITS
// ================================================================================================

/// Defines a cryptographic hash function.
pub trait Hasher {
    type Digest: Debug + Copy + AsRef<[u8]> + Default + Eq + PartialEq + Send + Sync;

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    /// Returns hash(seed || value). This method is intended for use in PRNG and PoW contexts.
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest;

    /// Reads the specified number of digests from the provided source, and returns the vector
    /// with the parsed digests as well as the number of bytes read from the source.
    ///
    /// Returns an error if there are not enough bytes in the source to read the specified
    /// number of digests.
    fn read_digests_into_vec<R: ByteReader>(
        source: &mut R,
        num_digests: usize,
    ) -> Result<Vec<Self::Digest>, DeserializationError>;
}

/// Defines a hash function for hashing field elements.
pub trait ElementHasher: Hasher {
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
    type Digest = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Digest {
        blake3::hash(bytes).into()
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        blake3::hash(values.as_bytes()).into()
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed);
        data[32..].copy_from_slice(&value.to_le_bytes());
        blake3::hash(&data).into()
    }

    fn read_digests_into_vec<R: ByteReader>(
        source: &mut R,
        num_digests: usize,
    ) -> Result<Vec<Self::Digest>, DeserializationError> {
        read_32_byte_digests(source, num_digests)
    }
}

impl<B: StarkField> ElementHasher for Blake3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        blake3::hash(bytes).into()
    }
}

// SHA3
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for SHA3 hash function with 256-bit
/// output.
pub struct Sha3_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha3_256<B> {
    type Digest = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Digest {
        sha3::Sha3_256::digest(bytes).into()
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        sha3::Sha3_256::digest(values.as_bytes()).into()
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed);
        data[32..].copy_from_slice(&value.to_le_bytes());
        sha3::Sha3_256::digest(&data).into()
    }

    fn read_digests_into_vec<R: ByteReader>(
        source: &mut R,
        num_digests: usize,
    ) -> Result<Vec<Self::Digest>, DeserializationError> {
        read_32_byte_digests(source, num_digests)
    }
}

impl<B: StarkField> ElementHasher for Sha3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        sha3::Sha3_256::digest(bytes).into()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn read_32_byte_digests<R: ByteReader>(
    source: &mut R,
    num_digests: usize,
) -> Result<Vec<[u8; 32]>, DeserializationError> {
    let mut result = Vec::with_capacity(num_digests);
    for _ in 0..num_digests {
        result.push(source.read_u8_array()?)
    }
    Ok(result)
}
