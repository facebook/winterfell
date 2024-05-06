use air::LagrangeKernelRandElements;
use alloc::string::ToString;
use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;
use utils::Deserializable;

// TODOP: Fix docs
/// A trait for generating the random elements required for constructing the auxiliary trace.
pub trait AuxProofVerifier {
    type AuxProof: Deserializable;
    type Error: ToString;

    /// Generates the random elements required for constructing the auxiliary trace. Optionally,
    /// verifies the auxiliary proof.
    fn verify<E, Hasher>(
        &self,
        aux_proof: Option<Self::AuxProof>,
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Option<LagrangeKernelRandElements<E>>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

// TODOP: Fix docs
/// Implementation of the [`AuxTraceVerifier`] trait that simply samples a given number of
/// elements.
#[derive(Debug, Clone, Default)]
pub struct DefaultAuxProofVerifier;

impl DefaultAuxProofVerifier {
    /// Creates a new [`DefaultAuxTraceVerifier`].
    pub fn new() -> Self {
        Self
    }
}

impl AuxProofVerifier for DefaultAuxProofVerifier {
    type AuxProof = ();
    type Error = RandomCoinError;

    fn verify<E, Hasher>(
        &self,
        aux_proof: Option<Self::AuxProof>,
        _public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Option<LagrangeKernelRandElements<E>>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        assert!(aux_proof.is_none());

        Ok(None)
    }
}
