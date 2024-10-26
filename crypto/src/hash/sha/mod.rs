// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;

use math::{FieldElement, StarkField};
use sha3::Digest;
use utils::ByteWriter;

use super::{ByteDigest, ElementHasher, Hasher};

// SHA3 WITH 256-BIT OUTPUT
// ================================================================================================

/// Implementation of the [Hasher](super::Hasher) trait for SHA3 hash function with 256-bit
/// output.
pub struct Sha3_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha3_256<B> {
    type Digest = ByteDigest<32>;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        ByteDigest(sha3::Sha3_256::digest(bytes).into())
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ByteDigest(sha3::Sha3_256::digest(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        ByteDigest(sha3::Sha3_256::digest(ByteDigest::digests_as_bytes(values)).into())
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        ByteDigest(sha3::Sha3_256::digest(data).into())
    }
}

impl<B: StarkField> ElementHasher for Sha3_256<B> {
    type BaseField = B;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_CANONICAL {
            // when element's internal and canonical representations are the same, we can hash
            // element bytes directly
            let bytes = E::elements_as_bytes(elements);
            ByteDigest(sha3::Sha3_256::digest(bytes).into())
        } else {
            // when elements' internal and canonical representations differ, we need to serialize
            // them before hashing
            let mut hasher = ShaHasher::new();
            hasher.write_many(elements);
            ByteDigest(hasher.finalize())
        }
    }
}

// SHA HASHER
// ================================================================================================

/// Wrapper around SHA3 hasher to implement [ByteWriter] trait for it.
struct ShaHasher(sha3::Sha3_256);

impl ShaHasher {
    pub fn new() -> Self {
        Self(sha3::Sha3_256::new())
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl ByteWriter for ShaHasher {
    fn write_u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn write_bytes(&mut self, values: &[u8]) {
        self.0.update(values);
    }
}
