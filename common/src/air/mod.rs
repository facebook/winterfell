// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{ComputationContext, ProofOptions};
use crypto::{Hasher, PublicCoin};
use math::{
    fft,
    field::{FieldElement, StarkField},
};
use std::collections::{BTreeSet, HashMap};
use utils::Serializable;

mod assertions;
pub use assertions::Assertion;

mod boundary;
pub use boundary::{BoundaryConstraint, BoundaryConstraintGroup};

mod transition;
pub use transition::{EvaluationFrame, TransitionConstraintDegree, TransitionConstraintGroup};

mod coefficients;
pub use coefficients::{ConstraintCompositionCoefficients, DeepCompositionCoefficients};

mod divisor;
pub use divisor::ConstraintDivisor;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const MIN_CYCLE_LENGTH: usize = 2;

// TRACE INFO
// ================================================================================================

pub struct TraceInfo {
    pub length: usize,
    pub meta: Vec<u8>,
}

// AIR TRAIT
// ================================================================================================

pub trait Air: Send + Sync {
    type BaseElement: StarkField;
    type PublicInputs: Serializable;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Should create a new instance of AIR for this computation from the provided parameters,
    /// which have the following meaning:
    /// - `trace_info` contains information about a concrete execution trace including trace
    ///   length, and optionally, additional custom parameters in `meta` field.
    /// - `public_inputs` specifies public inputs for this instance of the computation.
    /// - `options` defines proof generation options such as extension factor, hash function etc.
    ///   these options define security level of the proof and influence proof generation time.
    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self;

    /// Should return context for this instance of the computation.
    fn context(&self) -> &ComputationContext;

    /// Should evaluate transition constraints over the specified evaluation frame. The evaluations
    /// should be saved into the `results` slice.
    fn evaluate_transition<E: FieldElement + From<Self::BaseElement>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    );

    /// Should return a set of assertions against a concrete execution trace for this computation.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseElement>>;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns values for all periodic columns used during computation. These values will be
    /// used to compute column values at specific states of the computation and passed in to
    /// the evaluate_transition() method. The default implementation of this method returns an
    /// empty vector. For computations which rely on periodic columns this method should be
    /// overridden in the specialized implementation. Number of values for each periodic column
    /// must be a power of two.
    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseElement>> {
        Vec::new()
    }

    /// Returns polynomial for all periodic columns. These polynomials are interpolated from
    /// the values returned from the get_periodic_column_values() method.
    fn get_periodic_column_polys(&self) -> Vec<Vec<Self::BaseElement>> {
        // cache inverse twiddles for each cycle length so that we don't have to re-build them
        // for columns with identical cycle lengths
        let mut twiddle_map = HashMap::new();
        // iterate over all periodic columns and convert column values into polynomials
        self.get_periodic_column_values()
            .into_iter()
            .map(|mut column| {
                let cycle_length = column.len();
                assert!(
                    cycle_length >= MIN_CYCLE_LENGTH,
                    "number of values in a periodic column must be at least {}, but was {}",
                    MIN_CYCLE_LENGTH,
                    cycle_length
                );
                assert!(
                    cycle_length.is_power_of_two(),
                    "number of values in a periodic column must be a power of two, but was {}",
                    cycle_length
                );
                assert!(cycle_length <= self.trace_length(),
                    "number of values in a periodic column cannot exceed trace length {}, but was {}",
                    self.trace_length(),
                    cycle_length
                );

                // get twiddles for interpolation and interpolate values into a polynomial
                let inv_twiddles = twiddle_map
                    .entry(cycle_length)
                    .or_insert_with(|| fft::get_inv_twiddles::<Self::BaseElement>(cycle_length));
                fft::interpolate_poly(&mut column, &inv_twiddles);
                column
            })
            .collect()
    }

    /// Groups transition constraints together by their degree, and also assigns coefficients
    /// to each constraint. These coefficients will be used to compute random linear combination
    /// of transition constraints during constraint merging.
    fn get_transition_constraints<E: FieldElement + From<Self::BaseElement>>(
        &self,
        coefficients: &[(E, E)],
    ) -> Vec<TransitionConstraintGroup<E>> {
        assert_eq!(
            self.num_transition_constraints(),
            coefficients.len(),
            "number of transition constraints must match the number of coefficient tuples"
        );

        // We want to make sure that once we divide constraint polynomials by the divisor,
        // the degree of the resulting polynomial will be exactly equal to the composition degree.
        // For transition constraints, divisor degree = deg(trace). So, target degree for all
        // transitions constraints is simply: deg(composition) + deg(trace)
        let target_degree = self.composition_degree() + self.trace_poly_degree();

        // iterate over all transition constraint degrees, and assign each constraint to the
        // appropriate group based on degree
        let context = self.context();
        let mut groups = HashMap::new();
        for (i, degree) in context.transition_constraint_degrees().iter().enumerate() {
            let evaluation_degree = degree.get_evaluation_degree(self.trace_length());
            let degree_adjustment = (target_degree - evaluation_degree) as u32;
            let group = groups.entry(evaluation_degree).or_insert_with(|| {
                TransitionConstraintGroup::new(degree.clone(), degree_adjustment)
            });
            group.add(i, coefficients[i]);
        }

        // convert from hash map into a vector and return
        groups.into_iter().map(|e| e.1).collect()
    }

    /// Convert assertions returned from get_assertions() method into boundary constraints,
    /// assign coefficients to each constraint, and group the constraints by denominator. The
    /// coefficients will be used to compute random linear combination of boundary constraints
    /// during constraint merging.
    fn get_boundary_constraints<E: FieldElement + From<Self::BaseElement>>(
        &self,
        coefficients: &[(E, E)],
    ) -> Vec<BoundaryConstraintGroup<Self::BaseElement, E>> {
        // compute inverse of the trace domain generator; this will be used for offset
        // computations when creating sequence constraints
        let inv_g = self
            .context()
            .get_trace_domain_generator::<Self::BaseElement>()
            .inv();

        // cache inverse twiddles for multi-value assertions in this map so that we don't have
        // to re-build them for assertions with identical strides
        let mut twiddle_map = HashMap::new();

        // get the assertions for this computation and make sure that they are all valid in
        // the context of this computation; also, sort the assertions in the deterministic order
        // so that changing the order of assertions does not change random coefficients that
        // get assigned to them
        let assertions = prepare_assertions(self.get_assertions(), self.context());
        assert_eq!(
            assertions.len(),
            coefficients.len(),
            "number of assertions must match the number of coefficient tuples"
        );

        // iterate over all assertions, which are sorted first by stride and then by first_step
        // in ascending order
        let mut groups = HashMap::new();
        for (i, assertion) in assertions.into_iter().enumerate() {
            let key = (assertion.stride(), assertion.first_step());
            let group = groups.entry(key).or_insert_with(|| {
                BoundaryConstraintGroup::new(
                    ConstraintDivisor::from_assertion(&assertion, self.context()),
                    self.trace_poly_degree(),
                    self.composition_degree(),
                )
            });

            // add a new assertion constraint to the current group (last group in the list)
            group.add(assertion, inv_g, &mut twiddle_map, coefficients[i]);
        }

        // make sure groups are sorted by adjustment degree
        let mut groups = groups.into_iter().map(|e| e.1).collect::<Vec<_>>();
        groups.sort_by_key(|c| c.degree_adjustment());

        groups
    }

    // CONTEXT PASS-THROUGH METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns options which specify proof generation parameters for an instance of the
    /// computation described by this AIR.
    fn options(&self) -> &ProofOptions {
        &self.context().options()
    }

    /// Returns length of the execution trace for an instance of the computation described by
    /// this AIR. This is guaranteed to be a power of two.
    fn trace_length(&self) -> usize {
        self.context().trace_length()
    }

    /// Returns width of the execution trace for an instance of the computation described by
    /// this AIR.
    fn trace_width(&self) -> usize {
        self.context().trace_width()
    }

    /// Returns degree of trace polynomials for an instance of the computation described by
    /// this AIR. The degree is always trace_length - 1.
    fn trace_poly_degree(&self) -> usize {
        self.trace_length() - 1
    }

    /// Returns the generator of the trace domain for an instance of the computation described
    /// by this AIR.
    fn trace_domain_generator(&self) -> Self::BaseElement {
        self.context().get_trace_domain_generator()
    }

    /// Returns constraint evaluation domain blowup factor for the computation described by this
    /// AIR. The blowup factor is defined as the smallest power of two greater than or equal to
    /// the hightest transition constraint degree. For example, if the hightest transition
    /// constraint degree = 3, ce_blowup_factor will be set to 4.
    fn ce_blowup_factor(&self) -> usize {
        self.context().ce_blowup_factor()
    }

    /// Returns size of the constraint evaluation domain. This is guaranteed to be a power of
    /// two, and is equal to `trace_length` * `ce_blowup_factor`.
    fn ce_domain_size(&self) -> usize {
        self.trace_length() * self.ce_blowup_factor()
    }

    /// Returns the degree to which all constraint polynomials are normalized before they are
    /// composed together. This degree is one less than the size of constraint evaluation domain.
    fn composition_degree(&self) -> usize {
        self.ce_domain_size() - 1
    }

    /// Returns low-degree extension domain blowup factor for the computation described by this
    /// AIR. This is guaranteed to be a power of two, and is always either equal to or greater
    /// than ce_blowup_factor.
    fn lde_blowup_factor(&self) -> usize {
        self.context().options().blowup_factor()
    }

    /// Returns the size of the low-degree extension domain. This is guaranteed to be a power of
    /// two, and is equal to `trace_length` * `lde_blowup_factor`.
    fn lde_domain_size(&self) -> usize {
        self.trace_length() * self.lde_blowup_factor()
    }

    /// Returns the generator of the low-degree extension domain for an instance of the
    /// computation described by this AIR.
    fn lde_domain_generator(&self) -> Self::BaseElement {
        self.context().get_lde_domain_generator()
    }

    /// Returns the offset by which the domain for low-degree extension is shifted in relation
    /// to the execution trace domain.
    fn domain_offset(&self) -> Self::BaseElement {
        self.context().options().domain_offset()
    }

    /// Returns the number of transition constraints for an instance of the computation described
    /// by this AIR.
    fn num_transition_constraints(&self) -> usize {
        self.context().transition_constraint_degrees().len()
    }

    // LINEAR COMBINATION COEFFICIENTS
    // --------------------------------------------------------------------------------------------

    /// Returns coefficients needed for random linear combination during construction of constraint
    /// composition polynomial.
    fn get_constraint_composition_coeffs<E: FieldElement + From<Self::BaseElement>, H: Hasher>(
        &self,
        coin: &mut PublicCoin<Self::BaseElement, H>,
    ) -> ConstraintCompositionCoefficients<E> {
        let num_t_constraints = self.num_transition_constraints();
        let num_b_constraints = self.get_assertions().len(); // TODO: this is heavy; do something lighter

        ConstraintCompositionCoefficients {
            transition: (0..num_t_constraints).map(|_| coin.draw_pair()).collect(),
            boundary: (0..num_b_constraints).map(|_| coin.draw_pair()).collect(),
        }
    }

    /// Returns coefficients needed for random linear combinations during construction of DEEP
    /// composition polynomial.
    fn get_deep_composition_coeffs<E: FieldElement + From<Self::BaseElement>, H: Hasher>(
        &self,
        coin: &mut PublicCoin<Self::BaseElement, H>,
    ) -> DeepCompositionCoefficients<E> {
        let trace_width = self.trace_width();
        let num_composition_columns = self.ce_blowup_factor();

        DeepCompositionCoefficients {
            trace: (0..trace_width).map(|_| coin.draw_triple()).collect(),
            constraints: (0..num_composition_columns).map(|_| coin.draw()).collect(),
            degree: coin.draw_pair(),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Makes sure the assertions are valid in the context of this computation and don't overlap with
/// each other - i.e. no two assertions are placed against the same register and step combination.
fn prepare_assertions<B: StarkField>(
    assertions: Vec<Assertion<B>>,
    context: &ComputationContext,
) -> Vec<Assertion<B>> {
    // we use a sorted set to help us sort the assertions by their 'natural' order. The natural
    // order is defined as sorting first by stride, then by first step, and finally by register,
    // all in ascending order.
    let mut result = BTreeSet::<Assertion<B>>::new();

    for assertion in assertions.into_iter() {
        assertion
            .validate_trace_width(context.trace_width())
            .unwrap_or_else(|err| {
                panic!("assertion {} is invalid: {}", assertion, err);
            });
        assertion
            .validate_trace_length(context.trace_length())
            .unwrap_or_else(|err| {
                panic!("assertion {} is invalid: {}", assertion, err);
            });
        for a in result.iter().filter(|a| a.register == assertion.register) {
            assert!(
                !a.overlaps_with(&assertion),
                "assertion {} overlaps with assertion {}",
                assertion,
                a
            );
        }

        result.insert(assertion);
    }

    result.into_iter().collect()
}
