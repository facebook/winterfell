// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::ExecutionTrace;
use air::TraceInfo;
use math::{FieldElement, StarkField};
use utils::{iter_mut, uninit_vector, Serializable};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// CONSTANTS
// ================================================================================================

//const MIN_FRAGMENT_LENGTH: usize = 2;

// TRACE BUILDER TRAIT
// ================================================================================================

/// TODO: add docs
pub trait TraceBuilder: Send + Sync {
    type BaseField: StarkField;
    type PublicInputs: Serializable;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// TODO: add docs
    fn trace_info(&self) -> &TraceInfo;

    /// TODO: add docs
    fn init_state(&self, state: &mut [Self::BaseField], segment: usize);

    /// TODO: add docs
    fn update_state(&self, state: &mut [Self::BaseField], step: usize, segment: usize);

    /// TODO: add docs
    fn get_pub_inputs(&self, trace: &ExecutionTrace<Self::BaseField>) -> Self::PublicInputs;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// TODO: add docs
    fn build_trace(&self) -> ExecutionTrace<Self::BaseField> {
        let trace_length = self.trace_info().length();
        let trace_width = self.trace_info().width();

        let chunk_size = self.segment_length();

        let mut trace = unsafe {
            (0..trace_width)
                .map(|_| uninit_vector(trace_length))
                .collect::<Vec<_>>()
        };
        let mut chunks = build_chunks(&mut trace, chunk_size);

        iter_mut!(chunks).for_each(|chunk| {
            let mut state = vec![Self::BaseField::ZERO; trace_width];
            self.init_state(&mut state, chunk.index);
            chunk.update_row(0, &state);
            for step in 0..chunk_size - 1 {
                self.update_state(&mut state, step, chunk.index);
                chunk.update_row(step + 1, &state);
            }
        });

        ExecutionTrace::init(trace)
    }

    /// TODO: add docs
    fn segment_length(&self) -> usize {
        self.trace_info().length()
    }
}

// TRACE CHUNKS
// ================================================================================================

fn build_chunks<B: StarkField>(trace: &mut [Vec<B>], chunk_size: usize) -> Vec<TraceChunk<B>> {
    let trace_length = trace[0].len();
    let num_chunks = trace_length / chunk_size;

    let mut chunk_data = (0..num_chunks).map(|_| Vec::new()).collect::<Vec<_>>();
    trace.iter_mut().for_each(|column| {
        for (i, fragment) in column.chunks_mut(chunk_size).enumerate() {
            chunk_data[i].push(fragment);
        }
    });

    chunk_data
        .into_iter()
        .enumerate()
        .map(|(i, data)| TraceChunk { index: i, data })
        .collect()
}

struct TraceChunk<'a, B: StarkField> {
    index: usize,
    data: Vec<&'a mut [B]>,
}

impl<'a, B: StarkField> TraceChunk<'a, B> {
    /// Updates a single row in the fragment with provided data.
    pub fn update_row(&mut self, row_idx: usize, row_data: &[B]) {
        for (column, &value) in self.data.iter_mut().zip(row_data) {
            column[row_idx] = value;
        }
    }
}
