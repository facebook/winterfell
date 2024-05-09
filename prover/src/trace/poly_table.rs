// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::{proof::TraceOodFrame, LagrangeKernelEvaluationFrame};
use math::{FieldElement, StarkField};

use crate::{matrix::ColumnIter, ColMatrix};

// TRACE POLYNOMIAL TABLE
// ================================================================================================

/// Trace polynomials in coefficient from for all segments of the execution trace.
///
/// Coefficients of the polynomials for the main trace segment are always in the base field.
/// However, coefficients of the polynomials for the auxiliary trace segment (including
/// the Lagrange kernel polynomial when present) may be either in the base field, or in
/// the extension field, depending on whether extension field is being used.
pub struct TracePolyTable<E: FieldElement> {
    main_trace_polys: ColMatrix<E::BaseField>,
    aux_trace_polys: Option<ColMatrix<E>>,
    lagrange_kernel_poly: Option<Vec<E>>,
}

impl<E: FieldElement> TracePolyTable<E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new table of trace polynomials from the provided main trace segment polynomials.
    pub fn new(main_trace_polys: ColMatrix<E::BaseField>) -> Self {
        Self {
            main_trace_polys,
            aux_trace_polys: None,
            lagrange_kernel_poly: None,
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided auxiliary segment polynomials to this polynomial table.
    pub fn add_aux_segment(
        &mut self,
        aux_trace_polys: ColMatrix<E>,
        lagrange_kernel_column_idx: Option<usize>,
    ) {
        assert!(self.aux_trace_polys.is_none());
        assert_eq!(
            self.main_trace_polys.num_rows(),
            aux_trace_polys.num_rows(),
            "polynomials in auxiliary segment must be of the same size as in the main segment"
        );

        let mut aux_trace_polys = aux_trace_polys;
        if let Some(index) = lagrange_kernel_column_idx {
            self.lagrange_kernel_poly = Some(aux_trace_polys.remove_column(index));
        }
        self.aux_trace_polys = Some(aux_trace_polys);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the size of each polynomial - i.e. size of a vector needed to hold a polynomial.
    pub fn poly_size(&self) -> usize {
        self.main_trace_polys.num_rows()
    }

    /// Evaluates all trace polynomials (across all trace segments) at the specified point `x`.
    pub fn evaluate_at(&self, x: E) -> Vec<E> {
        let mut result = self.main_trace_polys.evaluate_columns_at(x);
        for aux_polys in self.aux_trace_polys.iter() {
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

        let lagrange_kernel_frame =
            self.lagrange_kernel_poly.as_ref().map(|lagrange_kernel_col_poly| {
                LagrangeKernelEvaluationFrame::from_lagrange_kernel_column_poly(
                    lagrange_kernel_col_poly,
                    z,
                )
            });

        let main_trace_width = self.main_trace_polys.num_cols();

        TraceOodFrame::new(current_row, next_row, main_trace_width, lagrange_kernel_frame)
    }

    /// Returns an iterator over the polynomials of the main trace segment.
    pub fn main_trace_polys(&self) -> impl Iterator<Item = &[E::BaseField]> {
        self.main_trace_polys.columns()
    }

    /// Returns an iterator over the polynomials of the auxiliary trace segment.
    pub fn aux_trace_polys(&self) -> impl Iterator<Item = &[E]> {
        match self.aux_trace_polys {
            Some(ref aux_segment_polys) => aux_segment_polys.columns(),
            None => ColumnIter::empty(),
        }
    }

    /// Returns the polynomial of the auxiliary trace segment corresponding to the Lagrange kernel,
    /// if any.
    pub fn lagrange_kernel_poly(&self) -> Option<&[E]> {
        self.lagrange_kernel_poly.as_deref()
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of polynomials in the main segment of the trace.
    #[cfg(test)]
    pub fn num_main_trace_polys(&self) -> usize {
        self.main_trace_polys.num_cols()
    }

    /// Returns a polynomial from the main segment of the trace at the specified index.
    #[cfg(test)]
    pub fn get_main_trace_poly(&self, idx: usize) -> &[E::BaseField] {
        self.main_trace_polys.get_column(idx)
    }
}
