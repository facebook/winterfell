use alloc::{string::ToString, vec::Vec};
use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;

/// A trait for generating the random elements required for constructing the auxiliary trace.
pub trait AuxRandElementsGenerator {
    type AuxRandElements<E: Send + Sync>;
    type Error: ToString;

    /// Generates the random elements required for constructing the auxiliary trace.
    fn generate_aux_rand_elements<E, Hasher>(
        &self,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Self::AuxRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

/// Implementation of the [`AuxRandElementsGenerator`] trait that simply samples a given number of
/// elements.
#[derive(Debug, Clone)]
pub struct DefaultAuxRandElementsGenerator {
    num_rand_elements: usize,
}

impl DefaultAuxRandElementsGenerator {
    /// Creates a new [`DefaultAuxRandElementsGenerator`].
    pub fn new(num_rand_elements: usize) -> Self {
        Self { num_rand_elements }
    }
}

impl AuxRandElementsGenerator for DefaultAuxRandElementsGenerator {
    type AuxRandElements<E: Send + Sync> = Vec<E>;
    type Error = RandomCoinError;

    fn generate_aux_rand_elements<E, Hasher>(
        &self,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Self::AuxRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        let mut rand_elements = Vec::with_capacity(self.num_rand_elements);

        for _ in 0..self.num_rand_elements {
            rand_elements.push(transcript.draw()?);
        }

        Ok(rand_elements)
    }
}
