// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::slice;

use math::fields::f64::BaseElement;
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
        let mut result = [0; 32];

        result[..8].copy_from_slice(&self.0[0].as_int().to_le_bytes());
        result[8..16].copy_from_slice(&self.0[1].as_int().to_le_bytes());
        result[16..24].copy_from_slice(&self.0[2].as_int().to_le_bytes());
        result[24..].copy_from_slice(&self.0[3].as_int().to_le_bytes());

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
        target.write_bytes(&self.as_bytes());
    }
}

impl Deserializable for ElementDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // TODO: check if the field elements are valid?
        let e1 = BaseElement::new(source.read_u64()?);
        let e2 = BaseElement::new(source.read_u64()?);
        let e3 = BaseElement::new(source.read_u64()?);
        let e4 = BaseElement::new(source.read_u64()?);

        Ok(Self([e1, e2, e3, e4]))
    }
}

impl From<[BaseElement; DIGEST_SIZE]> for ElementDigest {
    fn from(value: [BaseElement; DIGEST_SIZE]) -> Self {
        Self(value)
    }
}

impl From<ElementDigest> for [BaseElement; DIGEST_SIZE] {
    fn from(value: ElementDigest) -> Self {
        value.0
    }
}

impl From<ElementDigest> for [u8; 32] {
    fn from(value: ElementDigest) -> Self {
        value.as_bytes()
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
        assert_eq!(32, bytes.len());

        let mut reader = SliceReader::new(&bytes);
        let d2 = ElementDigest::read_from(&mut reader).unwrap();

        assert_eq!(d1, d2);
    }
}
