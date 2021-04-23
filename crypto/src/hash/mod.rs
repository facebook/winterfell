// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::HashFunction;
use core::fmt::Debug;
use math::field::FieldElement;
use sha3::Digest;
use utils::AsBytes;

// HASHER TRAIT
// ================================================================================================

pub trait Hasher {
    type Digest: Debug + Copy + AsRef<[u8]> + Default + Eq + PartialEq;

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest;

    fn hash_elements<E: FieldElement>(elements: &[E]) -> Self::Digest;

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
