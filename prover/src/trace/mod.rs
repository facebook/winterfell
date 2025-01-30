// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::{Air, AuxRandElements, EvaluationFrame, TraceInfo};
use math::{polynom, FieldElement, StarkField};

use super::ColMatrix;

mod trace_lde;
pub use trace_lde::{DefaultTraceLde, TraceLde};

mod poly_table;
pub use poly_table::TracePolyTable;

mod trace_table;
pub use trace_table::{TraceTable, TraceTableFragment};

#[cfg(test)]
mod tests;

// AUX TRACE WITH METADATA
// ================================================================================================

/// Holds the auxiliary trace, the random elements used when generating the auxiliary trace.
pub struct AuxTraceWithMetadata<E: FieldElement> {
    pub aux_trace: ColMatrix<E>,
    pub aux_rand_elements: AuxRandElements<E>,
}

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
    /// Returns trace info for this trace.
    fn info(&self) -> &TraceInfo;

    /// Returns a reference to a [Matrix] describing the main segment of this trace.
    fn main_segment(&self) -> &ColMatrix<Self::BaseField>;

    /// Reads an evaluation frame from the main trace segment at the specified row.
    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>);

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of rows in this trace.
    fn length(&self) -> usize {
        self.info().length()
    }

    /// Returns the number of columns in the main segment of this trace.
    fn main_trace_width(&self) -> usize {
        self.info().main_trace_width()
    }

    /// Returns the number of columns in the auxiliary trace segment.
    fn aux_trace_width(&self) -> usize {
        self.info().aux_segment_width()
    }

    /// Checks if this trace is valid against the specified AIR, and panics if not.
    ///
    /// NOTE: this is a very expensive operation and is intended for use only in debug mode.
    fn validate<A, E>(&self, air: &A, aux_trace_with_metadata: Option<&AuxTraceWithMetadata<E>>)
    where
        A: Air<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField>,
    {
        // make sure the width align; if they don't something went terribly wrong
        assert_eq!(
            self.main_trace_width(),
            air.trace_info().main_trace_width(),
            "inconsistent trace width: expected {}, but was {}",
            self.main_trace_width(),
            air.trace_info().main_trace_width(),
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

        // then, check assertions against the auxiliary trace segment
        if let Some(aux_trace_with_metadata) = aux_trace_with_metadata {
            let aux_trace = &aux_trace_with_metadata.aux_trace;
            let aux_rand_elements = &aux_trace_with_metadata.aux_rand_elements;

            for assertion in air.get_aux_assertions(aux_rand_elements) {
                // get the matrix and verify the assertion against it
                assertion.apply(self.length(), |step, value| {
                    assert!(
                        value == aux_trace.get(assertion.column(), step),
                        "trace does not satisfy assertion aux_trace({}, {}) == {}",
                        assertion.column(),
                        step,
                        value
                    );
                });
            }
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
                    "main transition constraint {i} did not evaluate to ZERO at step {step}"
                );
            }

            // evaluate transition constraints for the auxiliary trace segment (if any) and make
            // sure they all evaluate to zeros
            if let Some(ref mut aux_frame) = aux_frame {
                let aux_trace_with_metadata =
                    aux_trace_with_metadata.expect("expected aux trace to be present");
                let aux_trace = &aux_trace_with_metadata.aux_trace;
                let aux_rand_elements = &aux_trace_with_metadata.aux_rand_elements;

                read_aux_frame(aux_trace, step, aux_frame);
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
                        "auxiliary transition constraint {i} did not evaluate to ZERO at step {step}"
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

/// Reads an evaluation frame from the provided auxiliary segment.
///
/// This is probably not the most efficient implementation, but since we call this function only
/// for trace validation purposes (which is done in debug mode only), we don't care all that much
/// about its performance.
fn read_aux_frame<E>(aux_segment: &ColMatrix<E>, row_idx: usize, frame: &mut EvaluationFrame<E>)
where
    E: FieldElement,
{
    for (current_frame_cell, aux_segment_col) in
        frame.current_mut().iter_mut().zip(aux_segment.columns())
    {
        *current_frame_cell = aux_segment_col[row_idx];
    }

    let next_row_idx = (row_idx + 1) % aux_segment.num_rows();
    for (next_frame_cell, aux_segment_col) in frame.next_mut().iter_mut().zip(aux_segment.columns())
    {
        *next_frame_cell = aux_segment_col[next_row_idx];
    }
}
