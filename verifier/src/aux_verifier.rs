use alloc::string::ToString;
use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

pub trait AuxTraceVerifier {
    type AuxRandElements<E>;
    type Error: ToString;

    fn generate_aux_rand_elements<E, Hasher>(
        &self,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Self::AuxRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}
