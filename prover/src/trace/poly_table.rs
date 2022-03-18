// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{matrix::ColumnIter, Matrix};
use air::EvaluationFrame;
use math::{log2, FieldElement, StarkField};
use utils::collections::Vec;

// POLYNOMIAL TABLE
// ================================================================================================
pub struct TracePolyTable<B: StarkField>(Matrix<B>);

impl<B: StarkField> TracePolyTable<B> {
    /// Creates a new table of trace polynomials from the provided vectors.
    pub fn new(polys: Matrix<B>) -> Self {
        TracePolyTable(polys)
    }

    /// Returns the size of each polynomial - i.e. size of a vector needed to hold a polynomial.
    pub fn poly_size(&self) -> usize {
        self.0.num_rows()
    }

    /// Evaluates all trace polynomials the the specified point `x`.
    pub fn evaluate_at<E: FieldElement<BaseField = B>>(&self, x: E) -> Vec<E> {
        self.0.evaluate_columns_at(x)
    }

    /// Returns an out-of-domain evaluation frame constructed by evaluating trace polynomials
    /// for all registers at points z and z * g, where g is the generator of the trace domain.
    pub fn get_ood_frame<E: FieldElement<BaseField = B>>(&self, z: E) -> EvaluationFrame<E> {
        let g = E::from(B::get_root_of_unity(log2(self.poly_size())));
        EvaluationFrame::from_rows(self.evaluate_at(z), self.evaluate_at(z * g))
    }

    /// Returns the number of trace polynomials in the table.
    pub fn num_polys(&self) -> usize {
        self.0.num_cols()
    }

    /// Returns a trace polynomial at the specified index.
    #[cfg(test)]
    pub fn get_poly(&self, idx: usize) -> &[B] {
        &self.0.get_column(idx)
    }

    /// Returns an iterator over the polynomials of this table.
    pub fn iter(&self) -> ColumnIter<B> {
        self.0.columns()
    }
}
