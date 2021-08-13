// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ByteDigest, ElementHasher, Hasher};
use core::{convert::TryInto, fmt::Debug, marker::PhantomData};
use math::{FieldElement, StarkField};

#[cfg(test)]
mod tests;

// BLAKE3 256-BIT OUTPUT
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

// BLAKE3 192-BIT OUTPUT
// ================================================================================================

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
