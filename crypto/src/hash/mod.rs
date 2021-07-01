// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::DigestSerializationError;
use core::fmt::Debug;
use math::FieldElement;
use sha3::Digest;
use utils::{group_slice_elements, AsBytes};

// HASHER TRAIT
// ================================================================================================

pub trait Hasher {
    type Digest: Debug + Copy + AsRef<[u8]> + Default + Eq + PartialEq + Send + Sync;

    /// Returns a hash of the provided sequence of bytes.
    fn hash(bytes: &[u8]) -> Self::Digest;

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees.
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    /// Returns a hash of the provided digests concatenated together.
    fn merge_many(data: &[Self::Digest]) -> Self::Digest;

    /// Returns hash(seed || value). This method is intended for use in PRNG and PoW contexts.
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest;

    /// Returns a hash of the provided field elements.
    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest;

    /// Reads the specified number of digests from the provided source, and returns the vector
    /// with the parsed digests as well as the number of bytes read from the source.
    ///
    /// Returns an error if there are not enough bytes in the source to read the specified
    /// number of digests.
    fn read_digests_into_vec(
        source: &[u8],
        num_digests: usize,
    ) -> Result<(Vec<Self::Digest>, usize), DigestSerializationError>;
}

// BLAKE3
// ================================================================================================

#[derive(Debug, PartialEq, Eq)]
pub struct Blake3_256();

impl Hasher for Blake3_256 {
    type Digest = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Digest {
        blake3::hash(bytes).into()
    }

    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        blake3::hash(bytes).into()
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        blake3::hash(values.as_bytes()).into()
    }

    fn merge_many(data: &[Self::Digest]) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        for data in data.iter() {
            hasher.update(data);
        }
        hasher.finalize().into()
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed);
        data[32..].copy_from_slice(&value.to_le_bytes());
        blake3::hash(&data).into()
    }

    fn read_digests_into_vec(
        source: &[u8],
        num_digests: usize,
    ) -> Result<(Vec<Self::Digest>, usize), DigestSerializationError> {
        read_32_byte_digests(source, num_digests)
    }
}

// SHA3
// ================================================================================================

pub struct Sha3_256();

impl Hasher for Sha3_256 {
    type Digest = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Digest {
        sha3::Sha3_256::digest(bytes).into()
    }

    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        sha3::Sha3_256::digest(bytes).into()
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        sha3::Sha3_256::digest(values.as_bytes()).into()
    }

    fn merge_many(data: &[Self::Digest]) -> Self::Digest {
        let mut hasher = sha3::Sha3_256::new();
        for data in data.iter() {
            hasher.update(data);
        }
        hasher.finalize().into()
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed);
        data[32..].copy_from_slice(&value.to_le_bytes());
        sha3::Sha3_256::digest(&data).into()
    }

    fn read_digests_into_vec(
        source: &[u8],
        num_digests: usize,
    ) -> Result<(Vec<Self::Digest>, usize), DigestSerializationError> {
        read_32_byte_digests(source, num_digests)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn read_32_byte_digests(
    source: &[u8],
    num_digests: usize,
) -> Result<(Vec<[u8; 32]>, usize), DigestSerializationError> {
    if num_digests == 0 {
        return Ok((Vec::new(), 0));
    }

    let num_bytes = num_digests * 32;
    if num_bytes > source.len() {
        return Err(DigestSerializationError::TooFewBytesForDigests(
            num_digests,
            num_bytes,
            source.len(),
        ));
    }

    let result = group_slice_elements(&source[..num_bytes]).to_vec();
    Ok((result, num_bytes))
}
