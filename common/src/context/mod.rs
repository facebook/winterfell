// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{air::TransitionConstraintDegree, ProofOptions};
use math::{utils::log2, StarkField};

// TYPES AND INTERFACES
// ================================================================================================

#[derive(Clone)]
pub struct ComputationContext {
    options: ProofOptions,
    trace_width: usize,
    trace_length: usize,
    transition_constraint_degrees: Vec<TransitionConstraintDegree>,
    ce_blowup_factor: usize,
}

// COMPUTATION CONTEXT
// ================================================================================================

impl ComputationContext {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    pub const MIN_TRACE_LENGTH: usize = 8;

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

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

        ComputationContext {
            options,
            trace_width,
            trace_length,
            transition_constraint_degrees,
            ce_blowup_factor,
        }
    }

    // TRACE INFO
    // --------------------------------------------------------------------------------------------

    pub fn trace_width(&self) -> usize {
        self.trace_width
    }

    pub fn trace_length(&self) -> usize {
        self.trace_length
    }

    // CONSTRAINT INFO
    // --------------------------------------------------------------------------------------------

    pub fn lde_blowup_factor(&self) -> usize {
        self.options.blowup_factor()
    }

    pub fn lde_domain_size(&self) -> usize {
        self.trace_length * self.lde_blowup_factor()
    }

    pub fn ce_blowup_factor(&self) -> usize {
        self.ce_blowup_factor
    }

    pub fn ce_domain_size(&self) -> usize {
        self.trace_length * self.ce_blowup_factor()
    }

    pub fn transition_constraint_degrees(&self) -> &[TransitionConstraintDegree] {
        &self.transition_constraint_degrees
    }

    // OTHER PROPERTIES
    // --------------------------------------------------------------------------------------------

    pub fn options(&self) -> &ProofOptions {
        &self.options
    }

    pub fn domain_offset<B: StarkField>(&self) -> B {
        self.options.domain_offset()
    }

    // UTILITY FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Returns a generator of the trace domain in the specified STARK field.
    pub fn get_trace_domain_generator<B: StarkField>(&self) -> B {
        B::get_root_of_unity(log2(self.trace_length()))
    }

    /// Returns a generator of the LDE domain in the specified STARK field.
    pub fn get_lde_domain_generator<B: StarkField>(&self) -> B {
        B::get_root_of_unity(log2(self.lde_domain_size()))
    }

    /// Returns g^step, where g is the generator of trace domain.
    pub fn get_trace_domain_value_at<B: StarkField>(&self, step: usize) -> B {
        debug_assert!(
            step < self.trace_length,
            "step must be in the trace domain [0, {})",
            self.trace_length
        );
        let g = self.get_trace_domain_generator::<B>();
        g.exp((step as u64).into())
    }
}
