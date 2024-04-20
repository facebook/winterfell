use alloc::{string::ToString, vec::Vec};
use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;

pub trait AuxTraceVerifier {
    type AuxRandElements<E: Send + Sync>;
    type Error: ToString;

    fn generate_aux_rand_elements<E, Hasher>(
        &self,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Self::AuxRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

pub struct DefaultAuxTraceVerifier {
    num_rand_elements: usize,
}

impl DefaultAuxTraceVerifier {
    pub fn new(num_rand_elements: usize) -> Self {
        Self { num_rand_elements }
    }
}

impl AuxTraceVerifier for DefaultAuxTraceVerifier {
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
