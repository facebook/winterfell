// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crypto::{ElementHasher, RandomCoin};
use math::{ExtensionOf, FieldElement, StarkField, ToElements};

use super::{EvaluationFrame, GkrData, LagrangeConstraintsCompositionCoefficients};
mod s_column;
use s_column::SColumnConstraint;

mod lagrange;
pub use lagrange::{
    LagrangeKernelBoundaryConstraint, LagrangeKernelConstraints, LagrangeKernelEvaluationFrame,
    LagrangeKernelRandElements, LagrangeKernelTransitionConstraints,
};

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
    fn get_oracles(&self) -> &[LogUpGkrOracle];

    /// A vector of virtual periodic columns defined by their values in some given cycle.
    /// Note that the cycle lengths must be powers of 2.
    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        vec![]
    }

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
    fn build_query<E>(&self, frame: &EvaluationFrame<E>, query: &mut [E])
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
        periodic_values: &[F],
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

    /// Generates the data needed for running the univariate IOP for multi-linear evaluation of [1].
    ///
    /// This mainly generates the batching randomness used to batch a number of multi-linear
    /// evaluation claims and includes some additional data that is needed for building/verifying
    /// the univariate IOP for multi-linear evaluation of [1].
    ///
    /// This is the $\lambda$ randomness in section 5.2 in [1] but using different random values for
    /// each term instead of powers of a single random element.
    ///
    /// [1]: https://eprint.iacr.org/2023/1284
    fn generate_univariate_iop_for_multi_linear_opening_data<E, H>(
        &self,
        openings: Vec<Vec<E>>,
        eval_point: Vec<E>,
        public_coin: &mut impl RandomCoin<Hasher = H, BaseField = E::BaseField>,
    ) -> GkrData<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
        H: ElementHasher<BaseField = E::BaseField>,
    {
        let openings: Vec<E> =
            openings[0].clone().chunks(2).flat_map(|ops| [ops[0], ops[1]]).collect();
        public_coin.reseed(H::hash_elements(&openings));

        let folding_randomness: E = public_coin.draw().expect("failed to generate randomness");
        let batched_openings: Vec<E> =
            openings.chunks(2).map(|p| p[0] + folding_randomness * (p[1] - p[0])).collect();

        let mut batching_randomness = Vec::with_capacity(openings.len() - 1);
        for _ in 0..openings.len() - 1 {
            batching_randomness.push(public_coin.draw().expect("failed to generate randomness"))
        }
        let mut eval_point = eval_point;
        eval_point.push(folding_randomness);

        GkrData::new(
            LagrangeKernelRandElements::new(eval_point),
            batching_randomness,
            batched_openings,
            self.get_oracles().to_vec(),
        )
    }

    /// Returns a new [`LagrangeKernelConstraints`].
    fn get_lagrange_kernel_constraints<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        lagrange_composition_coefficients: LagrangeConstraintsCompositionCoefficients<E>,
        lagrange_kernel_rand_elements: &LagrangeKernelRandElements<E>,
    ) -> LagrangeKernelConstraints<E> {
        LagrangeKernelConstraints::new(
            lagrange_composition_coefficients,
            lagrange_kernel_rand_elements,
        )
    }

    /// Returns a new [`SColumnConstraints`].
    fn get_s_column_constraints<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        gkr_data: GkrData<E>,
        composition_coefficient: E,
    ) -> SColumnConstraint<E> {
        SColumnConstraint::new(gkr_data, composition_coefficient)
    }

    /// Returns the periodic values used in the LogUp-GKR statement, either as base field element
    /// during circuit evaluation or as extension field element during the run of sum-check for
    /// the input layer.
    fn build_periodic_values<E>(&self, num_rows: usize) -> PeriodicTable<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let table = self
            .get_periodic_column_values()
            .iter()
            .map(|values| values.iter().map(|x| E::from(*x)).collect())
            .collect();

        PeriodicTable { table, num_rows }
    }
}

#[derive(Clone, Default)]
pub(crate) struct PhantomLogUpGkrEval<B: StarkField, P: Clone + Send + Sync + ToElements<B>> {
    _field: PhantomData<B>,
    _public_inputs: PhantomData<P>,
}

impl<B, P> PhantomLogUpGkrEval<B, P>
where
    B: StarkField,
    P: Clone + Send + Sync + ToElements<B>,
{
    pub fn new() -> Self {
        Self {
            _field: PhantomData,
            _public_inputs: PhantomData,
        }
    }
}

impl<B, P> LogUpGkrEvaluator for PhantomLogUpGkrEval<B, P>
where
    B: StarkField,
    P: Clone + Send + Sync + ToElements<B>,
{
    type BaseField = B;

    type PublicInputs = P;

    fn get_oracles(&self) -> &[LogUpGkrOracle] {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }

    fn get_num_rand_values(&self) -> usize {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }

    fn get_num_fractions(&self) -> usize {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }

    fn max_degree(&self) -> usize {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }

    fn build_query<E>(&self, _frame: &EvaluationFrame<E>, _query: &mut [E])
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }

    fn evaluate_query<F, E>(
        &self,
        _query: &[F],
        _periodic_values: &[F],
        _rand_values: &[E],
        _numerator: &mut [E],
        _denominator: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + ExtensionOf<F>,
    {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }

    fn compute_claim<E>(&self, _inputs: &Self::PublicInputs, _rand_values: &[E]) -> E
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        panic!("LogUpGkrEvaluator method called but LogUp-GKR is not implemented")
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum LogUpGkrOracle {
    /// A column with a given index in the main trace segment.
    CurrentRow(usize),
    /// A column with a given index in the main trace segment but shifted upwards.
    NextRow(usize),
}

// PERIODIC COLUMNS FOR LOGUP
// =================================================================================================

/// Stores the periodic columns used in a LogUp-GKR statement.
///
/// Each stored periodic column is interpreted as a multi-linear extension polynomial of the column
/// with the given periodic values. Due to the periodic nature of the values, storing, binding of
/// an argument and evaluating the said multi-linear extension can be all done linearly in the size
/// of the smallest cycle defining the periodic values. Hence we only store the values of this
/// smallest cycle. The cycle is assumed throughout to be a power of 2.
#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord)]
pub struct PeriodicTable<E: FieldElement> {
    pub table: Vec<Vec<E>>,
    pub num_rows: usize,
}

impl<E> PeriodicTable<E>
where
    E: FieldElement,
{
    pub fn new(table: Vec<Vec<E::BaseField>>, num_rows: usize) -> Self {
        let table = table.iter().map(|col| col.iter().map(|x| E::from(*x)).collect()).collect();

        Self { table, num_rows }
    }

    pub fn num_columns(&self) -> usize {
        self.table.len()
    }

    pub fn table(&self) -> &[Vec<E>] {
        &self.table
    }

    pub fn fill_periodic_values_at(&self, row: usize, values: &mut [E]) {
        self.table
            .iter()
            .zip(values.iter_mut())
            .for_each(|(col, value)| *value = col[row % col.len()])
    }

    pub fn bind_least_significant_variable(&mut self, round_challenge: E) {
        for col in self.table.iter_mut() {
            if col.len() > 1 && self.num_rows <= col.len() {
                let num_evals = col.len() >> 1;
                for i in 0..num_evals {
                    col[i] = col[i] + round_challenge * (col[i + num_evals] - col[i]);
                }
                col.truncate(num_evals)
            }
        }
        self.num_rows /= 2;
    }
}
