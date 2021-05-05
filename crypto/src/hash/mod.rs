// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::HashFunction;
use core::fmt::Debug;
use math::field::FieldElement;
use sha3::Digest;
use utils::{group_slice_elements, AsBytes};

// HASHER TRAIT
// ================================================================================================

pub trait Hasher {
    type Digest: Debug + Copy + AsRef<[u8]> + Default + Eq + PartialEq;

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest;

    fn hash_with_int(seed: Self::Digest, value: u64) -> Self::Digest;

    fn read_digests_into_vec(source: &[u8], num_digests: usize) -> (Vec<Self::Digest>, usize);

    fn hash_fn() -> HashFunction;
}

// BLAKE3
// ================================================================================================

#[derive(Debug, PartialEq, Eq)]
pub struct Blake3_256();

impl Hasher for Blake3_256 {
    type Digest = [u8; 32];

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        blake3::hash(values.as_bytes()).into()
    }

    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        blake3::hash(&bytes).into()
    }

    fn hash_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 64];
        data[..32].copy_from_slice(&seed);
        data[56..].copy_from_slice(&value.to_le_bytes());
        blake3::hash(&data).into()
    }

    fn read_digests_into_vec(source: &[u8], num_digests: usize) -> (Vec<Self::Digest>, usize) {
        read_32_byte_digests(source, num_digests)
    }

    fn hash_fn() -> HashFunction {
        blake3
    }
}

/// Wrapper around blake3 hash function
pub fn blake3(values: &[u8], result: &mut [u8]) {
    debug_assert!(
        result.len() == 32,
        "expected result to be exactly 32 bytes but received {}",
        result.len()
    );
    let hash = blake3::hash(&values);
    result.copy_from_slice(hash.as_bytes());
}

// SHA3
// ================================================================================================

pub struct Sha3_256();

impl Hasher for Sha3_256 {
    type Digest = [u8; 32];

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        sha3::Sha3_256::digest(values.as_bytes()).into()
    }

    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest {
        let bytes = E::elements_as_bytes(elements);
        sha3::Sha3_256::digest(bytes).into()
    }

    fn read_digests_into_vec(source: &[u8], num_digests: usize) -> (Vec<Self::Digest>, usize) {
        read_32_byte_digests(source, num_digests)
    }

    fn hash_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 64];
        data[..32].copy_from_slice(&seed);
        data[56..].copy_from_slice(&value.to_le_bytes());
        sha3::Sha3_256::digest(&data).into()
    }

    fn hash_fn() -> HashFunction {
        sha3
    }
}

/// Wrapper around sha3 hash function
pub fn sha3(values: &[u8], result: &mut [u8]) {
    debug_assert!(
        result.len() == 32,
        "expected result to be exactly 32 bytes but received {}",
        result.len()
    );
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&values);
    let hash = hasher.finalize();
    result.copy_from_slice(hash.as_ref());
}

// HELPER FUNCTIONS
// ================================================================================================

fn read_32_byte_digests(source: &[u8], num_digests: usize) -> (Vec<[u8; 32]>, usize) {
    if num_digests == 0 {
        return (Vec::new(), 0);
    }

    let num_bytes = num_digests * 32;
    // TODO: return error instead of panicking
    assert!(source.len() >= num_bytes, "not enough bytes");

    let result = group_slice_elements(&source[..num_bytes]).to_vec();
    (result, num_bytes)
}
