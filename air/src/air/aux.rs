use alloc::{string::ToString, vec::Vec};
use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;
use utils::Deserializable;

use super::lagrange::LagrangeKernelRandElements;

/// Holds the randomly generated elements necessary to build the auxiliary trace.
///
/// Specifically, [`AuxRandElements`] currently supports 2 types of random elements:
/// - the ones needed to build the Lagrange kernel column (when using GKR to accelerate LogUp),
/// - the ones needed to build all the other auxiliary columns
#[derive(Debug, Clone)]
pub struct AuxRandElements<E> {
    rand_elements: Vec<E>,
    lagrange: Option<LagrangeKernelRandElements<E>>,
}

impl<E> AuxRandElements<E> {
    /// Creates a new [`AuxRandElements`], where the auxiliary trace doesn't contain a Lagrange
    /// kernel column.
    pub fn new(rand_elements: Vec<E>) -> Self {
        Self {
            rand_elements,
            lagrange: None,
        }
    }

    /// Creates a new [`AuxRandElements`], where the auxiliary trace contains a Lagrange kernel
    /// column.
    pub fn new_with_lagrange(
        rand_elements: Vec<E>,
        lagrange: Option<LagrangeKernelRandElements<E>>,
    ) -> Self {
        Self {
            rand_elements,
            lagrange,
        }
    }

    /// Returns the random elements needed to build all columns other than the Lagrange kernel one.
    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }

    /// Returns the random elements needed to build the Lagrange kernel column.
    pub fn lagrange(&self) -> Option<&LagrangeKernelRandElements<E>> {
        self.lagrange.as_ref()
    }
}

// TODOP: Talk more about GKR
/// A trait for verifying an auxiliary proof.
pub trait AuxProofVerifier {
    /// The auxiliary proof.
    type AuxProof: Deserializable;
    /// The error that can occur during auxiliary proof verification.
    type Error: ToString;

    /// Verifies the auxiliary proof, and returns the random elements that will be used in building
    /// the Lagrange kernel auxiliary column.
    fn verify<E, Hasher>(
        &self,
        aux_proof: Self::AuxProof,
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<LagrangeKernelRandElements<E>, Self::Error>
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
    ) -> Result<LagrangeKernelRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        Ok(LagrangeKernelRandElements::new(Vec::new()))
    }
}
