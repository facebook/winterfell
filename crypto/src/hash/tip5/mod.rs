use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::tip5;
use twenty_first::shared_math::tip5::Tip5;
use twenty_first::shared_math::tip5::DIGEST_LENGTH;
use twenty_first::shared_math::tip5::RATE;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use math::fields::f64::BaseElement;
use math::FieldElement;
use math::StarkField;
use utils::ByteReader;
use utils::ByteWriter;
use utils::Deserializable;
use utils::DeserializationError;
use utils::Serializable;

use crate::Digest;
use crate::Hasher;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tip5Digest([BaseElement; DIGEST_LENGTH]);

impl Tip5Digest {
    pub fn new(digest: [BaseElement; DIGEST_LENGTH]) -> Self {
        Self(digest)
    }

    pub fn as_elements(&self) -> &[BaseElement; DIGEST_LENGTH] {
        &self.0
    }
}

impl Serializable for Tip5Digest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.as_bytes());
    }
}

impl Deserializable for Tip5Digest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let read_values = [
            source.read_u64()?,
            source.read_u64()?,
            source.read_u64()?,
            source.read_u64()?,
            source.read_u64()?,
        ];
        if read_values.iter().any(|&x| x >= BaseElement::MODULUS) {
            return Err(DeserializationError::InvalidValue(
                "Read u64 must be a valid field element.".into(),
            ));
        }
        Ok(Self(read_values.map(BaseElement::new)))
    }
}

impl IntoIterator for Tip5Digest {
    type Item = BaseElement;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_elements().to_vec().into_iter()
    }
}

impl Digest for Tip5Digest {
    fn as_bytes(&self) -> [u8; 40] {
        self.into_iter()
            .flat_map(|element| element.as_int().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl Hasher for Tip5 {
    type Digest = Tip5Digest;
    const COLLISION_RESISTANCE: u32 = 160;

    fn hash(bytes: &[u8]) -> Self::Digest {
        let bytes_iterator = bytes.chunks_exact(8);
        let last_element = {
            let mut last_bytes = [0_u8; 8];
            last_bytes[..bytes_iterator.remainder().len()]
                .copy_from_slice(bytes_iterator.remainder());
            let last_element = u64::from_le_bytes(last_bytes);
            BFieldElement::new(last_element)
        };
        let hash_input = bytes_iterator
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .map(BFieldElement::new)
            .chain(std::iter::once(last_element))
            .collect::<Vec<_>>();
        let digest = Tip5::hash_varlen(&hash_input);
        let digest = digest.values().map(b_field_element_to_base_element);
        Tip5Digest::new(digest)
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let left_and_right = values.map(|digest| {
            let elements = digest.as_elements();
            let elements = elements.map(base_element_to_b_field_element);
            tip5::Digest::new(elements)
        });
        let digest = Tip5::hash_pair(&left_and_right[0], &left_and_right[1]);
        let digest = digest.values().map(b_field_element_to_base_element);
        Tip5Digest::new(digest)
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut initial_state = [BaseElement::ZERO; RATE];
        initial_state[..DIGEST_LENGTH].copy_from_slice(seed.as_elements());
        initial_state[DIGEST_LENGTH] = BaseElement::new(value);
        let initial_state = initial_state.map(base_element_to_b_field_element);
        let digest = Tip5::hash_10(&initial_state);
        let digest = digest.map(b_field_element_to_base_element);
        Tip5Digest::new(digest)
    }
}

fn base_element_to_b_field_element(base_element: BaseElement) -> BFieldElement {
    BFieldElement::from_raw_u64(base_element.inner())
}

fn b_field_element_to_base_element(b_field_element: BFieldElement) -> BaseElement {
    BaseElement::from_mont(b_field_element.raw_u64())
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use rand::Rng;

    use math::StarkField;

    use super::*;

    #[test]
    fn base_field_element_conversion() {
        let random_element: u64 = thread_rng().gen();

        let base_element = BaseElement::new(random_element);
        let b_field_element = base_element_to_b_field_element(base_element);
        let base_element = b_field_element_to_base_element(b_field_element);
        let inner_value_after_double_conversion = base_element.as_int();
        assert_eq!(random_element, inner_value_after_double_conversion);

        let b_field_element = BFieldElement::new(random_element);
        let base_element = b_field_element_to_base_element(b_field_element);
        let b_field_element = base_element_to_b_field_element(base_element);
        let inner_value_after_double_conversion = b_field_element.value();
        assert_eq!(random_element, inner_value_after_double_conversion);
    }
}
