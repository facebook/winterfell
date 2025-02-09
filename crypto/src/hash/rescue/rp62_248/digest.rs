// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::slice;

use math::{fields::f62::BaseElement, StarkField};
use utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use super::{Digest, DIGEST_SIZE};

// DIGEST TRAIT IMPLEMENTATIONS
// ================================================================================================

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ElementDigest([BaseElement; DIGEST_SIZE]);

impl ElementDigest {
    pub fn new(value: [BaseElement; DIGEST_SIZE]) -> Self {
        Self(value)
    }

    pub fn as_elements(&self) -> &[BaseElement] {
        &self.0
    }

    pub fn digests_as_elements(digests: &[Self]) -> &[BaseElement] {
        let p = digests.as_ptr();
        let len = digests.len() * DIGEST_SIZE;
        unsafe { slice::from_raw_parts(p as *const BaseElement, len) }
    }
}

impl Digest for ElementDigest {
    fn as_bytes(&self) -> [u8; 32] {
        let v1 = self.0[0].as_int();
        let v2 = self.0[1].as_int();
        let v3 = self.0[2].as_int();
        let v4 = self.0[3].as_int();

        let mut result = [0; 32];
        result[..8].copy_from_slice(&(v1 | (v2 << 62)).to_le_bytes());
        result[8..16].copy_from_slice(&((v2 >> 2) | (v3 << 60)).to_le_bytes());
        result[16..24].copy_from_slice(&((v3 >> 4) | (v4 << 58)).to_le_bytes());
        result[24..].copy_from_slice(&(v4 >> 6).to_le_bytes());

        result
    }
}

impl Default for ElementDigest {
    fn default() -> Self {
        ElementDigest([BaseElement::default(); DIGEST_SIZE])
    }
}

impl Serializable for ElementDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes()[..31]);
    }
}

impl Deserializable for ElementDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let v1 = source.read_u64()?;
        let v2 = source.read_u64()?;
        let v3 = source.read_u64()?;
        let v4 = source.read_u32()?;
        let v5 = source.read_u16()?;
        let v6 = source.read_u8()?;

        let e1 = BaseElement::new(v1 & 0x3fffffffffffffff);
        let e2 = BaseElement::new(((v2 << 4) >> 2) | (v1 >> 62) & 0x3fffffffffffffff);
        let e3 = BaseElement::new(((v3 << 6) >> 2) | (v2 >> 60) & 0x3fffffffffffffff);
        let e4 = BaseElement::new(
            (v3 >> 58) | ((v4 as u64) << 6) | ((v5 as u64) << 38) | ((v6 as u64) << 54),
        );

        Ok(Self([e1, e2, e3, e4]))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use rand_utils::rand_array;
    use utils::{Deserializable, Serializable, SliceReader};

    use super::ElementDigest;

    #[test]
    fn digest_serialization() {
        let d1 = ElementDigest(rand_array());

        let mut bytes = vec![];
        d1.write_into(&mut bytes);
        assert_eq!(31, bytes.len());

        let mut reader = SliceReader::new(&bytes);
        let d2 = ElementDigest::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }
}
