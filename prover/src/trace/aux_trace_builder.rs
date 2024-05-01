use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

use crate::matrix::ColMatrix;

/// Accesses the type of the auxiliary trace's random elements in the [`AuxTraceBuilder`].
pub type AuxRandElements<ATB, E> = <ATB as AuxTraceBuilder<E>>::AuxRandElements;

/// Accesses the type of the auxiliary proof in the [`AuxTraceBuilder`].
pub type AuxProof<ATB, E> = <ATB as AuxTraceBuilder<E>>::AuxProof;

/// Holds the auxiliary trace, random elements, and optionally, an auxiliary proof.
///
/// This type is returned by [`AuxTraceBuilder::build_aux_trace`].
pub struct AuxTraceWithMetadata<E: FieldElement, AuxRandEles, AuxProof> {
    pub aux_trace: ColMatrix<E>,
    pub aux_rand_eles: AuxRandEles,
    pub aux_proof: Option<AuxProof>,
}

/// Defines the interface for building the auxiliary trace.
pub trait AuxTraceBuilder<E: Send + Sync> {
    /// A type defining the random elements used in constructing the auxiliary trace.
    type AuxRandElements;

    /// Optionally, an extra proof object. If not needed, set to `()`.
    ///
    /// This is useful in cases where part of the auxiliary trace is proved outside of the STARK
    /// proof system.
    type AuxProof;

    /// Builds the auxiliary trace.
    fn build_aux_trace<Hasher>(
        self,
        main_trace: &ColMatrix<E::BaseField>,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> AuxTraceWithMetadata<E, Self::AuxRandElements, Self::AuxProof>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}
