// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Matrix;
use air::EvaluationFrame;
use core::iter::FusedIterator;
use math::{log2, FieldElement, StarkField};
use utils::collections::Vec;

// POLYNOMIAL TABLE
// ================================================================================================
pub struct TracePolyTable<B: StarkField> {
    main_segment_polys: Matrix<B>,
    aux_segment_polys: Vec<Matrix<B>>,
}

impl<B: StarkField> TracePolyTable<B> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new table of trace polynomials from the provided main trace segment polynomials.
    pub fn new(main_trace_polys: Matrix<B>) -> Self {
        TracePolyTable {
            main_segment_polys: main_trace_polys,
            aux_segment_polys: Vec::new(),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided auxiliary segment polynomials to this polynomial table.
    pub fn add_aux_segment(&mut self, segment_polys: Matrix<B>) {
        self.aux_segment_polys.push(segment_polys);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the size of each polynomial - i.e. size of a vector needed to hold a polynomial.
    pub fn poly_size(&self) -> usize {
        self.main_segment_polys.num_rows()
    }

    /// Evaluates all trace polynomials the the specified point `x`.
    pub fn evaluate_at<E: FieldElement<BaseField = B>>(&self, x: E) -> Vec<E> {
        let mut result = self.main_segment_polys.evaluate_columns_at(x);
        for aux_polys in self.aux_segment_polys.iter() {
            result.append(&mut aux_polys.evaluate_columns_at(x));
        }
        result
    }

    /// Returns an out-of-domain evaluation frame constructed by evaluating trace polynomials
    /// for all registers at points z and z * g, where g is the generator of the trace domain.
    pub fn get_ood_frame<E: FieldElement<BaseField = B>>(&self, z: E) -> EvaluationFrame<E> {
        let g = E::from(B::get_root_of_unity(log2(self.poly_size())));
        EvaluationFrame::from_rows(self.evaluate_at(z), self.evaluate_at(z * g))
    }

    /// Returns an iterator over the polynomials of this table.
    pub fn iter(&self) -> PolyIter<B> {
        let mut segments = vec![&self.main_segment_polys];
        self.aux_segment_polys.iter().for_each(|p| segments.push(p));
        PolyIter::new(segments)
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of trace polynomials in this table.
    #[cfg(test)]
    pub fn num_polys(&self) -> usize {
        self.main_segment_polys.num_cols()
            + self
                .aux_segment_polys
                .iter()
                .fold(0, |s, m| s + m.num_cols())
    }

    /// Returns a trace polynomial at the specified index.
    #[cfg(test)]
    pub fn get_poly(&self, idx: usize) -> &[B] {
        let mut offset = self.main_segment_polys.num_cols();
        if idx < offset {
            return &self.main_segment_polys.get_column(idx);
        }

        for segment_polys in self.aux_segment_polys.iter() {
            if idx < offset + segment_polys.num_cols() {
                return segment_polys.get_column(idx - offset);
            } else {
                offset += segment_polys.num_cols();
            }
        }

        panic!("invalid polynomial index {}", idx);
    }
}

// POLYNOMIAL ITERATOR
// ================================================================================================

pub struct PolyIter<'a, E: FieldElement> {
    segments: Vec<&'a Matrix<E>>,
    s_cursor: usize,
    p_cursor: usize,
}

impl<'a, E: FieldElement> PolyIter<'a, E> {
    pub fn new(segments: Vec<&'a Matrix<E>>) -> Self {
        Self {
            segments,
            s_cursor: 0,
            p_cursor: 0,
        }
    }
}

impl<'a, E: FieldElement> Iterator for PolyIter<'a, E> {
    type Item = &'a [E];

    fn next(&mut self) -> Option<Self::Item> {
        let matrix = self.segments[self.s_cursor];
        match matrix.num_cols() - self.p_cursor {
            0 => None,
            _ => {
                let column = matrix.get_column(self.p_cursor);
                self.p_cursor += 1;
                if self.p_cursor == matrix.num_cols() && self.s_cursor < self.segments.len() - 1 {
                    self.s_cursor += 1;
                    self.p_cursor = 0;
                }
                Some(column)
            }
        }
    }
}

impl<'a, E: FieldElement> ExactSizeIterator for PolyIter<'a, E> {
    fn len(&self) -> usize {
        self.segments.iter().fold(0, |s, m| s + m.num_cols())
    }
}

impl<'a, E: FieldElement> FusedIterator for PolyIter<'a, E> {}
