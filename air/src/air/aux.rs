use alloc::{string::ToString, vec::Vec};

use crypto::{ElementHasher, RandomCoin, RandomCoinError};
use math::FieldElement;
use utils::Deserializable;

use super::lagrange::LagrangeKernelRandElements;

// TODOP: fix all docs and naming
/// Holds the randomly generated elements necessary to build the auxiliary trace.
///
/// Specifically, [`AuxRandElements`] currently supports 2 types of random elements:
/// - the ones needed to build the Lagrange kernel column (when using GKR to accelerate LogUp),
/// - the ones needed to build all the other auxiliary columns
#[derive(Debug, Clone)]
pub struct AuxRandElements<E> {
    rand_elements: Vec<E>,
    gkr: Option<GkrRandElements<E>>,
}

impl<E> AuxRandElements<E> {
    /// Creates a new [`AuxRandElements`], where the auxiliary trace doesn't contain a Lagrange
    /// kernel column.
    pub fn new(rand_elements: Vec<E>) -> Self {
        Self { rand_elements, gkr: None }
    }

    /// Creates a new [`AuxRandElements`], where the auxiliary trace contains a Lagrange kernel
    /// column.
    pub fn new_with_gkr(rand_elements: Vec<E>, gkr: Option<GkrRandElements<E>>) -> Self {
        Self { rand_elements, gkr }
    }

    /// Returns the random elements needed to build all columns other than the Lagrange kernel one.
    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }

    /// Returns the random elements needed to build the Lagrange kernel column.
    pub fn lagrange(&self) -> Option<&LagrangeKernelRandElements<E>> {
        self.gkr.as_ref().map(|gkr| &gkr.lagrange)
    }

    pub fn gkr_lambdas(&self) -> Option<&[E]> {
        self.gkr.as_ref().map(|gkr| gkr.lambdas.as_ref())
    }
}

/// TODOP: Document and fix naming. Consider making this type private or pub(crate), depending on if
/// `AuxRandElements` exposes it (currently not).
#[derive(Clone, Debug)]
pub struct GkrRandElements<E> {
    lagrange: LagrangeKernelRandElements<E>,
    lambdas: Vec<E>,
}

impl<E> GkrRandElements<E> {
    pub fn new(lagrange: LagrangeKernelRandElements<E>, lambdas: Vec<E>) -> Self {
        Self { lagrange, lambdas }
    }

    pub fn lagrange_kernel_rand_elements(&self) -> &LagrangeKernelRandElements<E> {
        &self.lagrange
    }

    pub fn lambdas(&self) -> &[E] {
        &self.lambdas
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
        gkr_proof: Self::GkrProof,
        public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<GkrRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}

impl GkrVerifier for () {
    type GkrProof = ();
    type Error = RandomCoinError;

    fn verify<E, Hasher>(
        &self,
        _gkr_proof: Self::GkrProof,
        _public_coin: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> Result<GkrRandElements<E>, Self::Error>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>,
    {
        Ok(GkrRandElements::new(LagrangeKernelRandElements::default(), Vec::new()))
    }
}
