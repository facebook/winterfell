use alloc::{string::ToString, vec::Vec};
use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;
use utils::Deserializable;

use super::lagrange::LagrangeKernelRandElements;

/// TODOP: document
#[derive(Debug, Clone)]
pub struct AuxRandElements<E> {
    rand_elements: Vec<E>,
    lagrange: Option<LagrangeKernelRandElements<E>>,
}

impl<E> AuxRandElements<E> {
    pub fn new(rand_elements: Vec<E>) -> Self {
        Self {
            rand_elements,
            lagrange: None,
        }
    }

    pub fn new_with_lagrange(
        rand_elements: Vec<E>,
        lagrange: Option<LagrangeKernelRandElements<E>>,
    ) -> Self {
        Self {
            rand_elements,
            lagrange,
        }
    }

    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }

    pub fn lagrange(&self) -> Option<&LagrangeKernelRandElements<E>> {
        self.lagrange.as_ref()
    }
}

// TODOP: Fix docs
/// A trait for generating the random elements required for constructing the auxiliary trace.
pub trait AuxProofVerifier {
    type AuxProof: Deserializable;
    type Error: ToString;

    /// Generates the random elements required for constructing the auxiliary trace. Optionally,
    /// verifies the auxiliary proof.
    fn verify<E, Hasher>(
        &self,
        aux_proof: Self::AuxProof,
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
        _aux_proof: Self::AuxProof,
        _public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<Option<LagrangeKernelRandElements<E>>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        Ok(None)
    }
}
