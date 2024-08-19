// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use math::{fields::f64::BaseElement, ExtensionOf, FieldElement, StarkField, ToElements};

use super::EvaluationFrame;

/// A trait containing the necessary information in order to run the LogUp-GKR protocol of [1].
///
/// The trait contains useful information for running the GKR protocol as well as for implementing
/// the univariate IOP for multi-linear evaluation of Section 5 in [1] for the final evaluation
/// check resulting from GKR.
///
/// [1]: https://eprint.iacr.org/2023/1284
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
    ///
    /// This is equal to the max of $1 + deg_k(\text{numerator}_i) * deg_k(\text{denominator}_j)$ where
    /// $i$ and $j$ range over the number of numerators and denominators, respectively, and $deg_k$
    /// is the degree of a multi-variate polynomial in its $k$-th variable.
    fn max_degree(&self) -> usize;

    /// Builds a query from the provided main trace frame and periodic values.
    ///
    /// Note: it should be possible to provide an implementation of this method based on the
    /// information returned from `get_oracles()`. However, this implementation is likely to be
    /// expensive compared to the hand-written implementation. However, we could provide a test
    /// which verifies that `get_oracles()` and `build_query()` methods are consistent.
    fn build_query<E>(&self, frame: &EvaluationFrame<E>, periodic_values: &[E], query: &mut [E])
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
        logup_randomness: &[E],
        numerators: &mut [E],
        denominators: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>;

    /// Computes the final claim for the LogUp-GKR circuit.
    ///
    /// The default implementation of this method returns E::ZERO as it is expected that the
    /// fractional sums will cancel out. However, in cases when some boundary conditions need to
    /// be imposed on the LogUp-GKR relations, this method can be overridden to compute the final
    /// expected claim.
    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        E::ZERO
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum LogUpGkrOracle<B: StarkField> {
    CurrentRow(usize),
    NextRow(usize),
    PeriodicValue(Vec<B>),
}

impl LogUpGkrEvaluator for () {
    type BaseField = BaseElement;

    type PublicInputs = ();

    fn get_oracles(&self) -> Vec<LogUpGkrOracle<Self::BaseField>> {
        unimplemented!()
    }

    fn get_num_rand_values(&self) -> usize {
        unimplemented!()
    }

    fn get_num_fractions(&self) -> usize {
        unimplemented!()
    }

    fn max_degree(&self) -> usize {
        unimplemented!()
    }

    fn build_query<E>(&self, _frame: &EvaluationFrame<E>, _periodic_values: &[E], _query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        unimplemented!()
    }

    fn evaluate_query<F, E>(
        &self,
        _query: &[F],
        _rand_values: &[E],
        _numerator: &mut [E],
        _denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        unimplemented!()
    }

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        unimplemented!()
    }
}
