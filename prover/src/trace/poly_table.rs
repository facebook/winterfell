// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{matrix::ColumnIter, ColMatrix};
use air::{proof::TraceOodFrame, LagrangeKernelEvaluationFrame};
use alloc::vec::Vec;
use math::{FieldElement, StarkField};

// TRACE POLYNOMIAL TABLE
// ================================================================================================

/// Trace polynomials in coefficient from for all segments of the execution trace.
///
/// Coefficients of the polynomials for the main trace segment are always in the base field.
/// However, coefficients of the polynomials for the auxiliary trace segment may be either in the
/// base field, or in the extension field, depending on whether extension field is being used.
pub struct TracePolyTable<E: FieldElement> {
    main_segment_polys: ColMatrix<E::BaseField>,
    aux_segment_polys: Option<ColMatrix<E>>,
    lagrange_kernel_column_idx: Option<usize>,
}

impl<E: FieldElement> TracePolyTable<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new table of trace polynomials from the provided main trace segment polynomials.
    pub fn new(main_trace_polys: ColMatrix<E::BaseField>) -> Self {
        Self {
            main_segment_polys: main_trace_polys,
            aux_segment_polys: None,
            lagrange_kernel_column_idx: None,
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided auxiliary segment polynomials to this polynomial table.
    pub fn add_aux_segment(
        &mut self,
        aux_segment_polys: ColMatrix<E>,
        lagrange_kernel_column_idx: Option<usize>,
    ) {
        assert!(self.aux_segment_polys.is_none());
        assert_eq!(
            self.main_segment_polys.num_rows(),
            aux_segment_polys.num_rows(),
            "polynomials in auxiliary segment must be of the same size as in the main segment"
        );
        self.aux_segment_polys = Some(aux_segment_polys);
        self.lagrange_kernel_column_idx = lagrange_kernel_column_idx;
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the size of each polynomial - i.e. size of a vector needed to hold a polynomial.
    pub fn poly_size(&self) -> usize {
        self.main_segment_polys.num_rows()
    }

    /// Evaluates all trace polynomials (across all trace segments) at the specified point `x`.
    pub fn evaluate_at(&self, x: E) -> Vec<E> {
        let mut result = self.main_segment_polys.evaluate_columns_at(x);
        for aux_polys in self.aux_segment_polys.iter() {
            result.append(&mut aux_polys.evaluate_columns_at(x));
        }
        result
    }

    /// Returns an out-of-domain evaluation frame constructed by evaluating trace polynomials for
    /// all columns at points z and z * g, where g is the generator of the trace domain.
    /// Additionally, if the Lagrange kernel auxiliary column is present, we also evaluate that
    /// column over the points: z, z * g, z * g^2, z * g^4, ..., z * g^(2^(v-1)), where v =
    /// log(trace_len).
    pub fn get_ood_frame(&self, z: E) -> TraceOodFrame<E> {
        let log_trace_len = self.poly_size().ilog2();
        let g = E::from(E::BaseField::get_root_of_unity(log_trace_len));
        let current_row = self.evaluate_at(z);
        let next_row = self.evaluate_at(z * g);

        let lagrange_kernel_frame = self.lagrange_kernel_column_idx.map(|col_idx| {
            let aux_segment_poly = self
                .aux_segment_polys
                .as_ref()
                .expect("aux segment poly and lagrange kernel column idx are set together");
            let lagrange_kernel_col_poly = aux_segment_poly.get_column(col_idx);

            LagrangeKernelEvaluationFrame::from_lagrange_kernel_column_poly(
                lagrange_kernel_col_poly,
                z,
            )
        });

        let main_trace_width = self.main_segment_polys.num_cols();

        TraceOodFrame::new(current_row, next_row, main_trace_width, lagrange_kernel_frame)
    }

    /// Returns an iterator over the polynomials of the main trace segment.
    pub fn main_trace_polys(&self) -> impl Iterator<Item = &[E::BaseField]> {
        self.main_segment_polys.columns()
    }

    /// Returns an iterator over the polynomials of the auxiliary trace segment.
    pub fn aux_segment_polys(&self) -> impl Iterator<Item = &[E]> {
        match self.aux_segment_polys {
            Some(ref aux_segment_polys) => aux_segment_polys.columns(),
            None => ColumnIter::empty(),
        }
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of polynomials in the main segment of the trace.
    #[cfg(test)]
    pub fn num_main_trace_polys(&self) -> usize {
        self.main_segment_polys.num_cols()
    }

    /// Returns a polynomial from the main segment of the trace at the specified index.
    #[cfg(test)]
    pub fn get_main_trace_poly(&self, idx: usize) -> &[E::BaseField] {
        self.main_segment_polys.get_column(idx)
    }
}
