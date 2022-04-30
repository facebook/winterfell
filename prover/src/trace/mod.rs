// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{matrix::MultiColumnIter, Matrix};
use air::{Air, AuxTraceRandElements, EvaluationFrame, TraceInfo, TraceLayout};
use math::{polynom, FieldElement, StarkField};

mod trace_lde;
pub use trace_lde::TraceLde;

mod poly_table;
pub use poly_table::TracePolyTable;

mod trace_table;
pub use trace_table::{TraceTable, TraceTableFragment};

mod commitment;
pub use commitment::TraceCommitment;

#[cfg(test)]
mod tests;

// TRACE TRAIT
// ================================================================================================
/// Defines an execution trace of a computation.
///
/// Execution trace can be reduced to a two-dimensional matrix in which each row represents the
/// state of a computation at a single point in time and each column corresponds to an algebraic
/// column tracked over all steps of the computation.
///
/// Building a trace is required for STARK proof generation. An execution trace of a specific
/// instance of a computation must be supplied to [Prover::prove()](super::Prover::prove) method
/// to generate a STARK proof.
///
/// This crate exposes one concrete implementation of the [Trace] trait: [TraceTable]. This
/// implementation supports concurrent trace generation and should be sufficient in most
/// situations. However, if functionality provided by [TraceTable] is not sufficient, uses can
/// provide custom implementations of the [Trace] trait which better suit their needs.
pub trait Trace: Sized {
    /// Base field for this execution trace.
    ///
    /// All cells of this execution trace contain values which are elements in this field.
    type BaseField: StarkField;

    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns a description of how columns of this trace are arranged into trace segments.
    fn layout(&self) -> &TraceLayout;

    /// Returns the number of rows in this trace.
    fn length(&self) -> usize;

    /// Returns metadata associated with this trace.
    fn meta(&self) -> &[u8];

    /// Returns a reference to a [Matrix] describing the main segment of this trace.
    fn main_segment(&self) -> &Matrix<Self::BaseField>;

    /// Builds and returns the next auxiliary trace segment. If there are no more segments to
    /// build (i.e., the trace is complete), None is returned.
    ///
    /// The `aux_segments` slice contains a list of auxiliary trace segments built as a result
    /// of prior invocations of this function. Thus, for example, on the first invocation,
    /// `aux_segments` will be empty; on the second invocation, it will contain a single matrix
    /// (the one built during the first invocation) etc.
    fn build_aux_segment<E: FieldElement<BaseField = Self::BaseField>>(
        &mut self,
        aux_segments: &[Matrix<E>],
        rand_elements: &[E],
    ) -> Option<Matrix<E>>;

    /// Reads an evaluation frame from the main trace segment at the specified row.
    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns trace info for this trace.
    fn get_info(&self) -> TraceInfo {
        TraceInfo::new_multi_segment(self.layout().clone(), self.length(), self.meta().to_vec())
    }

    /// Returns the number of columns in the main segment of this trace.
    fn main_trace_width(&self) -> usize {
        self.layout().main_trace_width()
    }

    /// Returns the number of columns in all auxiliary trace segments.
    fn aux_trace_width(&self) -> usize {
        self.layout().aux_trace_width()
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------
    /// Checks if this trace is valid against the specified AIR, and panics if not.
    ///
    /// NOTE: this is a very expensive operation and is intended for use only in debug mode.
    fn validate<A, E>(
        &self,
        air: &A,
        aux_segments: &[Matrix<E>],
        aux_rand_elements: &AuxTraceRandElements<E>,
    ) where
        A: Air<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField>,
    {
        // make sure the width align; if they don't something went terribly wrong
        assert_eq!(
            self.main_trace_width(),
            air.trace_layout().main_trace_width(),
            "inconsistent trace width: expected {}, but was {}",
            self.main_trace_width(),
            air.trace_layout().main_trace_width(),
        );

        // --- 1. make sure the assertions are valid ----------------------------------------------

        // first, check assertions against the main segment of the execution trace
        for assertion in air.get_assertions() {
            assertion.apply(self.length(), |step, value| {
                assert!(
                    value == self.main_segment().get(assertion.column(), step),
                    "trace does not satisfy assertion main_trace({}, {}) == {}",
                    assertion.column(),
                    step,
                    value
                );
            });
        }

        // then, check assertions against auxiliary trace segments
        for assertion in air.get_aux_assertions(aux_rand_elements) {
            // find which segment the assertion is for and remap assertion column index to the
            // column index in the context of this segment
            let mut column_idx = assertion.column();
            let mut segment_idx = 0;
            for i in 0..self.layout().num_aux_segments() {
                let segment_width = self.layout().get_aux_segment_width(i);
                if column_idx < segment_width {
                    segment_idx = i;
                    break;
                }
                column_idx -= segment_width;
            }

            // get the matrix and verify the assertion against it
            assertion.apply(self.length(), |step, value| {
                assert!(
                    value == aux_segments[segment_idx].get(column_idx, step),
                    "trace does not satisfy assertion aux_trace({}, {}) == {}",
                    assertion.column(),
                    step,
                    value
                );
            });
        }

        // --- 2. make sure this trace satisfies all transition constraints -----------------------

        // collect the info needed to build periodic values for a specific step
        let g = air.trace_domain_generator();
        let periodic_values_polys = air.get_periodic_column_polys();
        let mut periodic_values = vec![Self::BaseField::ZERO; periodic_values_polys.len()];

        // initialize buffers to hold evaluation frames and results of constraint evaluations
        let mut x = Self::BaseField::ONE;
        let mut main_frame = EvaluationFrame::new(self.main_trace_width());
        let mut aux_frame = if air.trace_info().is_multi_segment() {
            Some(EvaluationFrame::<E>::new(self.aux_trace_width()))
        } else {
            None
        };
        let mut main_evaluations =
            vec![Self::BaseField::ZERO; air.context().num_main_transition_constraints()];
        let mut aux_evaluations = vec![E::ZERO; air.context().num_aux_transition_constraints()];

        // we check transition constraints on all steps except the last k steps, where k is the
        // number of steps exempt from transition constraints (guaranteed to be at least 1)
        for step in 0..self.length() - air.context().num_transition_exemptions() {
            // build periodic values
            for (p, v) in periodic_values_polys.iter().zip(periodic_values.iter_mut()) {
                let num_cycles = air.trace_length() / p.len();
                let x = x.exp((num_cycles as u32).into());
                *v = polynom::eval(p, x);
            }

            // evaluate transition constraints for the main trace segment and make sure they all
            // evaluate to zeros
            self.read_main_frame(step, &mut main_frame);
            air.evaluate_transition(&main_frame, &periodic_values, &mut main_evaluations);
            for (i, &evaluation) in main_evaluations.iter().enumerate() {
                assert!(
                    evaluation == Self::BaseField::ZERO,
                    "main transition constraint {} did not evaluate to ZERO at step {}",
                    i,
                    step
                );
            }

            // evaluate transition constraints for auxiliary trace segments (if any) and make
            // sure they all evaluate to zeros
            if let Some(ref mut aux_frame) = aux_frame {
                read_aux_frame(aux_segments, step, aux_frame);
                air.evaluate_aux_transition(
                    &main_frame,
                    aux_frame,
                    &periodic_values,
                    aux_rand_elements,
                    &mut aux_evaluations,
                );
                for (i, &evaluation) in aux_evaluations.iter().enumerate() {
                    assert!(
                        evaluation == E::ZERO,
                        "auxiliary transition constraint {} did not evaluate to ZERO at step {}",
                        i,
                        step
                    );
                }
            }

            // update x coordinate of the domain
            x *= g;
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Reads an evaluation frame from the set of provided auxiliary segments. This expects that
/// `aux_segments` contains at least one entry.
///
/// This is probably not the most efficient implementation, but since we call this function only
/// for trace validation purposes (which is done in debug mode only), we don't care all that much
/// about its performance.
fn read_aux_frame<E>(aux_segments: &[Matrix<E>], row_idx: usize, frame: &mut EvaluationFrame<E>)
where
    E: FieldElement,
{
    for (column, current_value) in MultiColumnIter::new(aux_segments).zip(frame.current_mut()) {
        *current_value = column[row_idx];
    }

    let next_row_idx = (row_idx + 1) % aux_segments[0].num_rows();
    for (column, next_value) in MultiColumnIter::new(aux_segments).zip(frame.next_mut()) {
        *next_value = column[next_row_idx];
    }
}
