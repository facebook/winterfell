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

/// A trait for verifying a GKR proof.
///
/// Specifically, the use case in mind is proving the constraints of a LogUp bus using GKR, as
/// described in [Improving logarithmic derivative lookups using
/// GKR](https://eprint.iacr.org/2023/1284.pdf).
pub trait GkrVerifier {
    /// The GKR proof.
    type GkrProof: Deserializable;
    /// The error that can occur during GKR proof verification.
    type Error: ToString;

    /// Verifies the GKR proof, and returns the random elements that were used in building
    /// the Lagrange kernel auxiliary column.
    fn verify<E, Hasher>(
        &self,
        aux_proof: Self::GkrProof,
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<LagrangeKernelRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

impl GkrVerifier for () {
    type GkrProof = ();
    type Error = RandomCoinError;

    fn verify<E, Hasher>(
        &self,
        _aux_proof: Self::GkrProof,
        _public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<LagrangeKernelRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        Ok(LagrangeKernelRandElements::new(Vec::new()))
    }
}
