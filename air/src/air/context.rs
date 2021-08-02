// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{air::TransitionConstraintDegree, ProofOptions, TraceInfo};
use math::{log2, StarkField};
use utils::collections::Vec;

// AIR CONTEXT
// ================================================================================================
/// STARK parameters and trace properties for a specific execution of a computation.
#[derive(Clone, PartialEq, Eq)]
pub struct AirContext<B: StarkField> {
    pub(super) options: ProofOptions,
    pub(super) trace_info: TraceInfo,
    pub(super) transition_constraint_degrees: Vec<TransitionConstraintDegree>,
    pub(super) ce_blowup_factor: usize,
    pub(super) trace_domain_generator: B,
    pub(super) lde_domain_generator: B,
}

impl<B: StarkField> AirContext<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns a new instance of [AirContext] instantiated from the specified parameters.
    ///
    /// The list of transition constraint degrees defines the total number of transition
    /// constraints and their expected degrees. Constraint evaluations computed by
    /// [Air::evaluate_transition()](crate::Air::evaluate_transition) function are expected to be
    /// in the order defined by this list.
    ///
    /// # Panics
    /// Panics if `transition_constraint_degrees` is an empty vector.
    pub fn new(
        trace_info: TraceInfo,
        transition_constraint_degrees: Vec<TransitionConstraintDegree>,
        options: ProofOptions,
    ) -> Self {
        assert!(
            !transition_constraint_degrees.is_empty(),
            "at least one transition constraint degree must be specified"
        );

        // determine minimum blowup factor needed to evaluate transition constraints by taking
        // the blowup factor of the highest degree constraint
        let mut ce_blowup_factor = 0;
        for degree in transition_constraint_degrees.iter() {
            if degree.min_blowup_factor() > ce_blowup_factor {
                ce_blowup_factor = degree.min_blowup_factor();
            }
        }

        assert!(
            options.blowup_factor() >= ce_blowup_factor,
            "blowup factor too small; expected at least {}, but was {}",
            ce_blowup_factor,
            options.blowup_factor()
        );

        let trace_length = trace_info.length();
        let lde_domain_size = trace_length * options.blowup_factor();

        AirContext {
            options,
            trace_info,
            transition_constraint_degrees,
            ce_blowup_factor,
            trace_domain_generator: B::get_root_of_unity(log2(trace_length)),
            lde_domain_generator: B::get_root_of_unity(log2(lde_domain_size)),
        }
    }
}
