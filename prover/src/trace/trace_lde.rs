// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Matrix;
use air::EvaluationFrame;
use math::FieldElement;
use utils::collections::Vec;

// TRACE LOW DEGREE EXTENSION
// ================================================================================================
/// TODO: add docs
pub struct TraceLde<E: FieldElement> {
    main_segment_lde: Matrix<E::BaseField>,
    aux_segment_ldes: Vec<Matrix<E>>,
    blowup: usize,
}

impl<E: FieldElement> TraceLde<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new trace low-degree extension table from the provided main trace segment LDE.
    pub fn new(main_trace_lde: Matrix<E::BaseField>, blowup: usize) -> Self {
        Self {
            main_segment_lde: main_trace_lde,
            aux_segment_ldes: Vec::new(),
            blowup,
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided auxiliary segment LDE to this trace LDE.
    pub fn add_aux_segment(&mut self, aux_segment_lde: Matrix<E>) {
        assert_eq!(
            self.main_segment_lde.num_rows(),
            aux_segment_lde.num_rows(),
            "number of rows in auxiliary segment must be of the same as in the main segment"
        );
        self.aux_segment_ldes.push(aux_segment_lde);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in the main segment of the execution trace.
    pub fn main_trace_width(&self) -> usize {
        self.main_segment_lde.num_cols()
    }

    /// Returns number of columns in the auxiliary segments of the execution trace.
    pub fn aux_trace_width(&self) -> usize {
        self.aux_segment_ldes
            .iter()
            .fold(0, |s, m| s + m.num_cols())
    }

    /// Returns the number of rows in the execution trace.
    pub fn trace_len(&self) -> usize {
        self.main_segment_lde.num_rows()
    }

    /// Returns blowup factor which was used to extend original execution trace into trace LDE.
    pub fn blowup(&self) -> usize {
        self.blowup
    }

    /// Reads current and next rows from the main trace segment into the specified frame.
    pub fn read_main_trace_frame_into<F: EvaluationFrame<E::BaseField>>(
        &self,
        lde_step: usize,
        frame: &mut F,
    ) {
        // copy main trace segment values into the frame
        frame.read_from(&self.main_segment_lde, lde_step, 0, self.blowup());
    }

    /// Reads current and next rows from the auxiliary trace segment into the specified frame.
    #[allow(dead_code)]
    pub fn read_aux_trace_frame_into<F: EvaluationFrame<E>>(&self, lde_step: usize, frame: &mut F) {
        //copy auxiliary trace segment values into the frame
        let mut offset = 0;
        for segment in self.aux_segment_ldes.iter() {
            frame.read_from(segment, lde_step, offset, self.blowup());
            offset += segment.num_cols();
        }
    }

    /// Returns a reference to [Matrix] representing the main trace segment.
    pub fn get_main_segment(&self) -> &Matrix<E::BaseField> {
        &self.main_segment_lde
    }

    /// Returns a reference to a [Matrix] representing an auxiliary trace segment at the specified
    /// index.
    pub fn get_aux_segment(&self, aux_segment_idx: usize) -> &Matrix<E> {
        &self.aux_segment_ldes[aux_segment_idx]
    }
}
