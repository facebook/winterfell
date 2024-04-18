use crypto::{ElementHasher, RandomCoin};
use math::FieldElement;

use crate::matrix::ColMatrix;

pub struct AuxTraceWithMetadata<E: FieldElement, AuxRandEles, AuxProof> {
    pub aux_trace: ColMatrix<E>,
    pub aux_rand_eles: AuxRandEles,
    pub aux_proof: Option<AuxProof>,
}

pub trait AuxTraceBuilder {
    type AuxRandEles<E>;
    type AuxParams;

    /// Optionally, an extra proof object. If not needed, set to `()`.
    ///
    /// This is useful in cases where part of the auxiliary trace is proved outside of the STARK
    /// proof system.
    type AuxProof;

    /// Builds the auxiliary trace.
    fn build_aux_trace<E, Hasher>(
        &mut self,
        main_trace: &ColMatrix<E::BaseField>,
        aux_params: Self::AuxParams,
        transcript: &mut impl RandomCoin<BaseField = E::BaseField, Hasher = Hasher>,
    ) -> AuxTraceWithMetadata<E, Self::AuxRandEles<E>, Self::AuxProof>
    where
        E: FieldElement,
        Hasher: ElementHasher<BaseField = E::BaseField>;
}
