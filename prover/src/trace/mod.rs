// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{matrix::MultiColumnIter, ColMatrix};
use air::{
    trace_aux_segment_has_only_lagrange_kernel_column, Air, AuxTraceRandElements, EvaluationFrame,
    TraceInfo,
};
use math::{log2, polynom, FieldElement, StarkField};

mod trace_lde;
pub use trace_lde::{DefaultTraceLde, TraceLde};

mod poly_table;
pub use poly_table::TracePolyTable;

mod trace_table;
pub use trace_table::{TraceTable, TraceTableFragment};

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
    /// Returns trace info for this trace.
    fn info(&self) -> &TraceInfo;

    /// Returns a reference to a [Matrix] describing the main segment of this trace.
    fn main_segment(&self) -> &ColMatrix<Self::BaseField>;

    /// Builds and returns the next auxiliary trace segment. If there are no more segments to build
    /// (i.e., the trace is complete), None is returned.
    ///
    /// The `aux_segments` slice contains a list of auxiliary trace segments built as a result of
    /// prior invocations of this function. Thus, for example, on the first invocation,
    /// `aux_segments` will be empty; on the second invocation, it will contain a single matrix (the
    /// one built during the first invocation) etc.
    ///
    /// The `rand_elements` slice contains the random elements to use to build the aux segment. If a
    /// Lagrange kernel column is present, the `lagrange_kernel_rand_elements` should be used. See
    /// [`Air::lagrange_kernel_rand_elements`] for more details.
    fn build_aux_segment<E: FieldElement<BaseField = Self::BaseField>>(
        &mut self,
        aux_segments: &[ColMatrix<E>],
        rand_elements: &[E],
        lagrange_kernel_rand_elements: Option<&[E]>,
    ) -> Option<ColMatrix<E>>;

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

    /// Returns the number of columns in all auxiliary trace segments.
    fn aux_trace_width(&self) -> usize {
        self.info().aux_trace_width()
    }

    /// Checks if this trace is valid against the specified AIR, and panics if not.
    ///
    /// NOTE: this is a very expensive operation and is intended for use only in debug mode.
    fn validate<A, E>(
        &self,
        air: &A,
        aux_segments: &[ColMatrix<E>],
        aux_rand_elements: &AuxTraceRandElements<E>,
    ) where
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

        // then, check assertions against auxiliary trace segments
        for assertion in air.get_aux_assertions(aux_rand_elements) {
            // find which segment the assertion is for and remap assertion column index to the
            // column index in the context of this segment
            let mut column_idx = assertion.column();
            let mut segment_idx = 0;
            for i in 0..self.info().num_aux_segments() {
                let segment_width = self.info().get_aux_segment_width(i);
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

        // then, check the Lagrange kernel assertion, if any
        if let Some(assertion) = air.get_lagrange_kernel_aux_assertion(aux_rand_elements) {
            let lagrange_kernel_col_idx = air
                .trace_info()
                .lagrange_kernel_aux_column_idx()
                .expect("Lagranged kernel column idx expected to be present");
            assertion.apply(self.length(), |step, value| {
                assert_eq!(
                    value,
                    aux_segments[0].get(lagrange_kernel_col_idx, step),
                    "trace does not satisfy assertion aux_trace({}, {}) == {}",
                    lagrange_kernel_col_idx,
                    step,
                    value
                )
            })
        }

        // --- 2. make sure this trace satisfies all transition constraints -----------------------

        // collect the info needed to build periodic values for a specific step
        let g = air.trace_domain_generator();
        let periodic_values_polys = air.get_periodic_column_polys();
        let mut periodic_values = vec![Self::BaseField::ZERO; periodic_values_polys.len()];

        // initialize buffers to hold evaluation frames and results of constraint evaluations
        let mut x = Self::BaseField::ONE;
        let mut main_frame = EvaluationFrame::new(self.main_trace_width());
        let mut aux_frame = if air.trace_info().is_multi_segment()
            && !trace_aux_segment_has_only_lagrange_kernel_column(
                air.context().lagrange_kernel_aux_column_idx(),
                air.trace_info(),
            ) {
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
                        "auxiliary transition constraint {i} did not evaluate to ZERO at step {step}"
                    );
                }
            }

            // update x coordinate of the domain
            x *= g;
        }

        // evaluate transition constraints for Lagrange kernel column (if any) and make sure
        // they all evaluate to zeros
        if let Some(col_idx) = self.info().lagrange_kernel_aux_column_idx() {
            let c = aux_segments[0].get_column(col_idx);
            let v = log2(self.length()) as usize;
            let r = aux_rand_elements.get_segment_elements(0);

            // Loop over every constraint
            for constraint_idx in 1..v + 1 {
                let domain_step = 2_usize.pow((v - constraint_idx + 1) as u32);
                let domain_half_step = 2_usize.pow((v - constraint_idx) as u32);

                // Every transition constraint has a different enforcement domain (i.e. the rows to which it applies).
                let enforcement_dom_len = self.length() / domain_step;
                for dom_idx in 0..enforcement_dom_len {
                    let x_current = dom_idx * domain_step;
                    let x_next = x_current + domain_half_step;

                    let evaluation = (r[v - constraint_idx] * c[x_current])
                        - ((E::ONE - r[v - constraint_idx]) * c[x_next]);

                    assert!(
                        evaluation == E::ZERO,
                        "Lagrange transition constraint {constraint_idx} did not evaluate to ZERO at step {x_current}"
                    );
                }
            }
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
fn read_aux_frame<E>(aux_segments: &[ColMatrix<E>], row_idx: usize, frame: &mut EvaluationFrame<E>)
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
