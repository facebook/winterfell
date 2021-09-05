// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::ExecutionTrace;
use air::TraceInfo;
use math::{FieldElement, StarkField};
use utils::Serializable;

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// TRACE BUILDER TRAIT
// ================================================================================================

/// TODO: add docs
pub trait TraceBuilder: Send + Sync {
    type BaseField: StarkField;
    type PublicInputs: Serializable;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    fn trace_info(&self) -> &TraceInfo;

    fn init_state(&self, state: &mut [Self::BaseField], segment: usize);

    fn update_state(&self, state: &mut [Self::BaseField], step: usize, segment: usize);

    fn get_public_inputs(&self, trace: &ExecutionTrace<Self::BaseField>) -> Self::PublicInputs;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    fn build_trace(&self) -> ExecutionTrace<Self::BaseField> {
        let trace_length = self.trace_info().length();
        let trace_width = self.trace_info().width();

        let mut trace = ExecutionTrace::new(trace_width, trace_length);

        let fragment_length = self.segment_length();

        trace.fragments(fragment_length).for_each(|mut fragment| {
            let mut state = vec![Self::BaseField::ZERO; trace_width];
            self.init_state(&mut state, fragment.index());
            fragment.update_row(0, &state);
            for step in 0..fragment.length() - 1 {
                self.update_state(&mut state, step, fragment.index());
                fragment.update_row(step + 1, &state);
            }
        });

        trace
    }

    fn segment_length(&self) -> usize {
        self.trace_info().length()
    }
}
