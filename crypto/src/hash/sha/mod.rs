// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ByteDigest, ElementHasher, Hasher};
use core::marker::PhantomData;
use math::{FieldElement, StarkField};
use sha3::Digest;

// SHA3 WITH 256-BIT OUTPUT
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
