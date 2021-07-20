// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{air::TransitionConstraintDegree, ProofOptions};
use math::{log2, StarkField};

// AIR CONTEXT
// ================================================================================================
/// STARK parameters and trace properties for a specific execution of a computation.
#[derive(Clone, PartialEq, Eq)]
pub struct AirContext<B: StarkField> {
    pub(super) options: ProofOptions,
    pub(super) trace_width: usize,
    pub(super) trace_length: usize,
    pub(super) transition_constraint_degrees: Vec<TransitionConstraintDegree>,
    pub(super) ce_blowup_factor: usize,
    pub(super) trace_domain_generator: B,
    pub(super) lde_domain_generator: B,
}

impl<B: StarkField> AirContext<B> {
    ///
    pub const MIN_TRACE_LENGTH: usize = 8;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    ///
    pub fn new(
        trace_width: usize,
        trace_length: usize,
        transition_constraint_degrees: Vec<TransitionConstraintDegree>,
        options: ProofOptions,
    ) -> Self {
        assert!(
            trace_width > 0,
            "trace_width must be greater than 0; was {}",
            trace_width
        );
        assert!(
            trace_length >= Self::MIN_TRACE_LENGTH,
            "trace_length must beat least {}; was {}",
            Self::MIN_TRACE_LENGTH,
            trace_length
        );
        assert!(
            trace_length.is_power_of_two(),
            "trace_length must be a power of 2; was {}",
            trace_length
        );
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

        let lde_domain_size = trace_length * options.blowup_factor();

        AirContext {
            options,
            trace_width,
            trace_length,
            transition_constraint_degrees,
            ce_blowup_factor,
            trace_domain_generator: B::get_root_of_unity(log2(trace_length)),
            lde_domain_generator: B::get_root_of_unity(log2(lde_domain_size)),
        }
    }
}
