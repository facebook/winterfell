use alloc::{string::ToString, vec::Vec};
use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;

/// Accesses the type of the auxiliary proof in the [`AuxTraceVerifier`].
pub type AuxProof<ATV> = <ATV as AuxTraceVerifier>::AuxProof;

/// A trait for generating the random elements required for constructing the auxiliary trace.
pub trait AuxTraceVerifier {
    type AuxRandElements<E: Send + Sync>;
    type AuxProof;
    type Error: ToString;

    /// Generates the random elements required for constructing the auxiliary trace. Optionally,
    /// verifies the auxiliary proof.
    fn verify_aux_trace<E, Hasher>(
        &self,
        aux_proof: Option<Self::AuxProof>,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Self::AuxRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

/// Implementation of the [`AuxRandElementsGenerator`] trait that simply samples a given number of
/// elements.
pub struct DefaultAuxTraceVerifier {
    num_rand_elements: usize,
}

impl DefaultAuxTraceVerifier {
    /// Creates a new [`DefaultAuxTraceVerifier`].
    pub fn new(num_rand_elements: usize) -> Self {
        Self { num_rand_elements }
    }
}

impl AuxTraceVerifier for DefaultAuxTraceVerifier {
    type AuxRandElements<E: Send + Sync> = Vec<E>;
    type AuxProof = ();
    type Error = RandomCoinError;

    fn verify_aux_trace<E, Hasher>(
        &self,
        aux_proof: Option<Self::AuxProof>,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Self::AuxRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        assert!(aux_proof.is_none());
        let mut rand_elements = Vec::with_capacity(self.num_rand_elements);

        for _ in 0..self.num_rand_elements {
            rand_elements.push(transcript.draw()?);
        }

        Ok(rand_elements)
    }
}
