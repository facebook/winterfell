// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{AirContext, Assertion, ConstraintDivisor};
use math::{ExtensionOf, FieldElement};
use utils::collections::{BTreeMap, BTreeSet, Vec};

mod constraint;
pub use constraint::BoundaryConstraint;

mod constraint_group;
pub use constraint_group::BoundaryConstraintGroup;

#[cfg(test)]
mod tests;

// BOUNDARY CONSTRAINT INFO
// ================================================================================================

/// Boundary constraints for a computation.
///
/// Boundary constraints are arranged into two categories: constraints against columns of the main
/// trace segment, and constraints against columns of auxiliary trace segments. Within each
/// category, the constraints are grouped by their divisor (see [BoundaryConstraintGroup] for
/// more info on boundary constraint structure).
///
/// When the protocol is run in a large field, types `B` and `E` are the same. However, when
/// working with small fields, these types are used as follows:
/// * Constraints against columns of the main segment of the execution trace are defined over the
///   field specified by `B`.
/// * Constraints against columns of auxiliary segments of the execution trace (if any) are defined
///   over the field specified by `E`.
/// * Constraint composition coefficients are defined over the field specified by `E`.
/// * Constraint divisors are defined over the field specified by `B`.
pub struct BoundaryConstraints<E: FieldElement> {
    main_constraints: Vec<BoundaryConstraintGroup<E::BaseField, E>>,
    aux_constraints: Vec<BoundaryConstraintGroup<E, E>>,
}

impl<E: FieldElement> BoundaryConstraints<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [BoundaryConstraints] for a computation described by the provided
    /// assertions and AIR context.
    ///
    /// # Panics
    /// Panics if:
    /// * The number of provided assertions does not match the number of assertions described by
    ///   the context.
    /// * The number of assertions does not match the number of the provided composition
    ///   coefficients.
    /// * The specified assertions are not valid in the context of the computation (e.g., assertion
    ///   column index is out of bounds).
    pub fn new(
        context: &AirContext<E::BaseField>,
        main_assertions: Vec<Assertion<E::BaseField>>,
        aux_assertions: Vec<Assertion<E>>,
        composition_coefficients: &[(E, E)],
    ) -> Self {
        // make sure the provided assertions are consistent with the specified context
        assert_eq!(
            main_assertions.len(),
            context.num_main_assertions,
            "expected {} assertions against main trace segment, but received {}",
            context.num_main_assertions,
            main_assertions.len(),
        );

        assert_eq!(
            aux_assertions.len(),
            context.num_aux_assertions,
            "expected {} assertions against auxiliary trace segments, but received {}",
            context.num_aux_assertions,
            aux_assertions.len(),
        );

        assert_eq!(
            context.num_assertions(),
            composition_coefficients.len(),
            "number of assertions must match the number of composition coefficient tuples"
        );

        let trace_length = context.trace_info.length();
        let main_trace_width = context.trace_info.layout().main_trace_width();
        let aux_trace_width = context.trace_info.layout().aux_trace_width();

        // make sure the assertions are valid in the context of their respective trace segments;
        // also, sort the assertions in the deterministic order so that changing the order of
        // assertions does not change random coefficients that get assigned to them.
        let main_assertions = prepare_assertions(main_assertions, main_trace_width, trace_length);
        let aux_assertions = prepare_assertions(aux_assertions, aux_trace_width, trace_length);

        // compute inverse of the trace domain generator; this will be used for offset
        // computations when creating sequence constraints
        let inv_g = context.trace_domain_generator.inv();

        // cache inverse twiddles for multi-value assertions in this map so that we don't have
        // to re-build them for assertions with identical strides
        let mut twiddle_map = BTreeMap::new();

        // split composition coefficients into main and auxiliary parts
        let (main_composition_coefficients, aux_composition_coefficients) =
            composition_coefficients.split_at(main_assertions.len());

        // build constraints for the assertions against the main trace segment
        let main_constraints = group_constraints(
            main_assertions,
            context,
            main_composition_coefficients,
            inv_g,
            &mut twiddle_map,
        );

        // build constraints for the assertions against auxiliary trace segments
        let aux_constraints = group_constraints(
            aux_assertions,
            context,
            aux_composition_coefficients,
            inv_g,
            &mut twiddle_map,
        );

        Self {
            main_constraints,
            aux_constraints,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the boundary constraints against the main segment of an execution
    /// trace. The constraints are grouped by their divisors.
    pub fn main_constraints(&self) -> &[BoundaryConstraintGroup<E::BaseField, E>] {
        &self.main_constraints
    }

    /// Returns a reference to the boundary constraints against auxiliary segments of an execution
    /// trace. The constraints are grouped by their divisors.
    pub fn aux_constraints(&self) -> &[BoundaryConstraintGroup<E, E>] {
        &self.aux_constraints
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Translates the provided assertions into boundary constraints, groups the constraints by their
/// divisor, and sorts the resulting groups by the degree adjustment factor.
fn group_constraints<F, E>(
    assertions: Vec<Assertion<F>>,
    context: &AirContext<F::BaseField>,
    composition_coefficients: &[(E, E)],
    inv_g: F::BaseField,
    twiddle_map: &mut BTreeMap<usize, Vec<F::BaseField>>,
) -> Vec<BoundaryConstraintGroup<F, E>>
where
    F: FieldElement,
    E: FieldElement<BaseField = F::BaseField> + ExtensionOf<F>,
{
    // iterate over all assertions, which are sorted first by stride and then by first_step
    // in ascending order
    let mut groups = BTreeMap::new();
    for (assertion, &cc) in assertions.into_iter().zip(composition_coefficients) {
        let key = (assertion.stride(), assertion.first_step());
        let group = groups.entry(key).or_insert_with(|| {
            BoundaryConstraintGroup::new(
                ConstraintDivisor::from_assertion(&assertion, context.trace_len()),
                context.trace_poly_degree(),
                context.composition_degree(),
            )
        });

        // add a new assertion constraint to the current group (last group in the list)
        group.add(assertion, inv_g, twiddle_map, cc);
    }

    // make sure groups are sorted by adjustment degree
    let mut groups = groups.into_iter().map(|e| e.1).collect::<Vec<_>>();
    groups.sort_by_key(|c| c.degree_adjustment());

    groups
}

/// Makes sure the assertions are valid in the context of this computation and don't overlap with
/// each other - i.e. no two assertions are placed against the same column and step combination.
///
/// This also sorts the assertions in their 'natural order'. The natural order is defined as
/// sorting first by stride, then by first step, and finally by column, all in ascending order.
fn prepare_assertions<E: FieldElement>(
    assertions: Vec<Assertion<E>>,
    trace_width: usize,
    trace_length: usize,
) -> Vec<Assertion<E>> {
    // we use a sorted set to help us sort the assertions by their 'natural' order
    let mut result = BTreeSet::<Assertion<E>>::new();

    for assertion in assertions.into_iter() {
        assertion
            .validate_trace_width(trace_width)
            .unwrap_or_else(|err| {
                panic!("assertion {} is invalid: {}", assertion, err);
            });
        assertion
            .validate_trace_length(trace_length)
            .unwrap_or_else(|err| {
                panic!("assertion {} is invalid: {}", assertion, err);
            });
        for a in result.iter().filter(|a| a.column == assertion.column) {
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
