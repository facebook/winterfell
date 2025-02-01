// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::Air;
use math::FieldElement;

use super::{super::TraceLde, CompositionPolyTrace, ConstraintEvaluationTable, StarkDomain};

mod default;
pub use default::DefaultConstraintEvaluator;

mod boundary;
use boundary::BoundaryConstraints;

mod periodic_table;
use periodic_table::PeriodicValueTable;

// CONSTRAINT EVALUATOR TRAIT
// ================================================================================================

/// Contains logic for evaluating AIR constraints over an extended execution trace.
///
/// The logic for evaluating AIR constraints over a single evaluation frame is defined by the [Air]
/// associated type, and the purpose of this trait is to execute this logic over all evaluation
/// frames in an extended execution trace.
pub trait ConstraintEvaluator<E: FieldElement> {
    /// AIR constraints for the computation described by this evaluator.
    type Air: Air<BaseField = E::BaseField>;

    /// Evaluates constraints against the provided extended execution trace, combines them into
    /// evaluations of a single polynomial, and returns these evaluations.
    ///
    /// Constraints are evaluated over a constraint evaluation domain. This is an optimization
    /// because constraint evaluation domain can be many times smaller than the full LDE domain.
    fn evaluate<T: TraceLde<E>>(
        self,
        trace: &T,
        domain: &StarkDomain<E::BaseField>,
    ) -> CompositionPolyTrace<E>;
}
