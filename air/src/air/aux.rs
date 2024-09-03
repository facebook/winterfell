// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use math::{ExtensionOf, FieldElement};

use super::{LagrangeKernelRandElements, LogUpGkrOracle};

/// Holds the randomly generated elements used in defining the auxiliary segment of the trace.
///
/// Specifically, [`AuxRandElements`] currently supports 2 types of random elements:
/// - the ones needed to build all the auxiliary columns except for the ones associated
///   to LogUp-GKR.
/// - the ones needed to build the "s" and Lagrange kernel auxiliary columns (when using GKR to
///   accelerate LogUp). These also include additional information needed to evaluate constraints
///   one these two columns.
#[derive(Debug, Clone)]
pub struct AuxRandElements<E: FieldElement> {
    rand_elements: Vec<E>,
    gkr: Option<GkrData<E>>,
}

impl<E: FieldElement> AuxRandElements<E> {
    /// Creates a new [`AuxRandElements`], where the auxiliary segment may contain columns needed when
    /// using GKR to accelerate LogUp (i.e. a Lagrange kernel column and the "s" column).
    pub fn new(rand_elements: Vec<E>, gkr: Option<GkrData<E>>) -> Self {
        Self { rand_elements, gkr }
    }
    /// Returns the random elements needed to build all columns other than the two GKR-related ones.
    pub fn rand_elements(&self) -> &[E] {
        &self.rand_elements
    }

    /// Returns the random elements needed to build the Lagrange kernel column.
    pub fn lagrange(&self) -> Option<&LagrangeKernelRandElements<E>> {
        self.gkr.as_ref().map(|gkr| &gkr.lagrange_kernel_eval_point)
    }

    /// Returns the random values used to linearly combine the openings returned from the GKR proof.
    ///
    /// These correspond to the lambdas in our documentation.
    pub fn gkr_openings_combining_randomness(&self) -> Option<&[E]> {
        self.gkr.as_ref().map(|gkr| gkr.openings_combining_randomness.as_ref())
    }

    /// Returns a collection of data necessary for implementing the univariate IOP for multi-linear
    /// evaluations of [1] when LogUp-GKR is enabled, else returns a `None`.
    ///
    /// [1]: https://eprint.iacr.org/2023/1284
    pub fn gkr_data(&self) -> Option<GkrData<E>> {
        self.gkr.clone()
    }
}

/// Holds all the data needed when using LogUp-GKR in order to build and verify the correctness of
/// two extra auxiliary columns required for running the univariate IOP for multi-linear
/// evaluations of [1].
///
/// This consists of:
/// 1. The Lagrange kernel random elements (expanded on in [`LagrangeKernelRandElements`]). These
///    make up the evaluation point of the multi-linear extension polynomials underlying the oracles
///    in point 4 below.
/// 2. The "openings combining randomness".
/// 3. The openings of the multi-linear extension polynomials of the main trace columns involved
///    in LogUp.
/// 4. A description of the each of the oracles involved in LogUp.
///
/// After verifying the LogUp-GKR circuit, the verifier is left with unproven claims provided
/// by the prover about the evaluations of the MLEs of the main trace columns at the evaluation
/// point defining the Lagrange kernel. Those claims are (linearly) batched into one using the
/// openings combining randomness and checked against the batched oracles using univariate IOP
/// for multi-linear evaluations of [1].
///
/// [1]: https://eprint.iacr.org/2023/1284
#[derive(Clone, Debug)]
pub struct GkrData<E: FieldElement> {
    pub lagrange_kernel_eval_point: LagrangeKernelRandElements<E>,
    pub openings_combining_randomness: Vec<E>,
    pub openings: Vec<E>,
    pub oracles: Vec<LogUpGkrOracle<E::BaseField>>,
}

impl<E: FieldElement> GkrData<E> {
    /// Constructs a new [`GkrData`] from [`LagrangeKernelRandElements`], the openings combining
    /// randomness and the LogUp-GKR oracles.
    ///
    /// See [`GkrData`] for a more detailed description.
    pub fn new(
        lagrange_kernel_eval_point: LagrangeKernelRandElements<E>,
        openings_combining_randomness: Vec<E>,
        openings: Vec<E>,
        oracles: Vec<LogUpGkrOracle<E::BaseField>>,
    ) -> Self {
        Self {
            lagrange_kernel_eval_point,
            openings_combining_randomness,
            openings,
            oracles,
        }
    }

    /// Returns the random elements needed to build the Lagrange kernel column.
    pub fn lagrange_kernel_rand_elements(&self) -> &LagrangeKernelRandElements<E> {
        &self.lagrange_kernel_eval_point
    }

    /// Returns the random values used to linearly combine the openings returned from the GKR proof.
    pub fn openings_combining_randomness(&self) -> &[E] {
        &self.openings_combining_randomness
    }

    pub fn openings(&self) -> &[E] {
        &self.openings
    }

    pub fn oracles(&self) -> &[LogUpGkrOracle<E::BaseField>] {
        &self.oracles
    }

    pub fn compute_batched_claim(&self) -> E {
        self.openings[0]
            + self
                .openings
                .iter()
                .skip(1)
                .zip(self.openings_combining_randomness.iter())
                .fold(E::ZERO, |acc, (a, b)| acc + *a * *b)
    }

    pub fn compute_batched_query<F>(&self, query: &[F]) -> E
    where
        F: FieldElement<BaseField = E::BaseField>,
        E: ExtensionOf<F>,
    {
        E::from(query[0])
            + query
                .iter()
                .skip(1)
                .zip(self.openings_combining_randomness.iter())
                .fold(E::ZERO, |acc, (a, b)| acc + b.mul_base(*a))
    }
}
