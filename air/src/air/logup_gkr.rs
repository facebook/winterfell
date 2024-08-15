// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use super::EvaluationFrame;
use math::{ExtensionOf, FieldElement, StarkField, ToElements};

pub trait LogUpGkrEvaluator: Clone + Sync {
    /// Defines the base field of the evaluator.
    type BaseField: StarkField;

    /// Public inputs need to compute the final claim.
    type PublicInputs: ToElements<Self::BaseField> + Send;

    /// Gets a list of all oracles involved in LogUp-GKR; this is intended to be used in construction of
    /// MLEs.
    fn get_oracles(&self) -> Vec<LogUpGkrOracle<Self::BaseField>>;

    /// Returns the number of random values needed to evaluate a query.
    fn get_num_rand_values(&self) -> usize;

    /// Returns the number of fractions in the LogUp-GKR statement.
    fn get_num_fractions(&self) -> usize;

    /// Returns the maximal degree of the multi-variate associated to the input layer.
    fn max_degree(&self) -> usize;

    /// Builds a query from the provided main trace frame and periodic values.
    ///
    /// Note: it should be possible to provide an implementation of this method based on the
    /// information returned from `get_oracles()`. However, this implementation is likely to be
    /// expensive compared to the hand-written implementation. However, we could provide a test
    /// which verifies that `get_oracles()` and `build_query()` methods are consistent.
    fn build_query<E>(&self, frame: &EvaluationFrame<E>, periodic_values: &[E]) -> Vec<E>
    where
        E: FieldElement<BaseField = Self::BaseField>;

    /// Evaluates the provided query and writes the results into the numerators and denominators.
    ///
    /// Note: it is also possible to combine `build_query()` and `evaluate_query()` into a single
    /// method to avoid the need to first build the query struct and then evaluate it. However:
    /// - We assume that the compiler will be able to optimize this away.
    /// - Merging the methods will make it more difficult avoid inconsistencies between
    ///   `evaluate_query()` and `get_oracles()` methods.
    fn evaluate_query<F, E>(
        &self,
        query: &[F],
        rand_values: &[E],
        numerator: &mut [E],
        denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>;

    /// Computes the final claim for the LogUp-GKR circuit.
    ///
    /// The default implementation of this method returns E::ZERO as it is expected that the
    /// fractional sums will cancel out. However, in cases when some boundary conditions need to
    /// be imposed on the LogUp-GKR relations, this method can be overridden to compute the final
    /// expected claim.
    fn compute_claim<E>(&self, inputs: &Self::PublicInputs, rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>;
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum LogUpGkrOracle<B: StarkField> {
    CurrentRow(usize),
    NextRow(usize),
    PeriodicValue(Vec<B>),
}
