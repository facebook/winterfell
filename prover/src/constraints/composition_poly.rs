// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::ColMatrix;
use math::{polynom::degree_of, FieldElement};
use utils::collections::Vec;

// COMPOSITION POLYNOMIAL
// ================================================================================================
/// Represents a composition polynomial split into columns with each column being of length equal
/// to trace_length. Thus, for example, if the composition polynomial has degree 2N - 1, where N
/// is the trace length, it will be stored as two columns of size N (each of degree N - 1).
pub struct CompositionPoly<E: FieldElement> {
    data: ColMatrix<E>,
}

impl<E: FieldElement> CompositionPoly<E> {
    /// Returns a new composition polynomial.
    pub fn new(coefficients: Vec<E>, trace_length: usize, num_cols: usize) -> Self {
        assert!(
            coefficients.len().is_power_of_two(),
            "size of composition polynomial must be a power of 2, but was {}",
            coefficients.len(),
        );
        assert!(
            trace_length.is_power_of_two(),
            "trace length must be a power of 2, but was {trace_length}"
        );
        assert!(
            trace_length < coefficients.len(),
            "trace length must be smaller than size of composition polynomial"
        );

        let polys = segment(coefficients, trace_length, num_cols);

        CompositionPoly {
            data: ColMatrix::new(polys),
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of individual column polynomials used to describe this composition
    /// polynomial.
    pub fn num_columns(&self) -> usize {
        self.data.num_cols()
    }

    /// Returns the length of individual column polynomials; this is guaranteed to be a power of 2.
    pub fn column_len(&self) -> usize {
        self.data.num_rows()
    }

    /// Returns the degree of individual column polynomial.
    #[allow(unused)]
    pub fn column_degree(&self) -> usize {
        self.column_len() - 1
    }

    /// Returns evaluations of all composition polynomial columns at point z.
    pub fn evaluate_at(&self, z: E) -> Vec<E> {
        self.data.evaluate_columns_at(z)
    }

    /// Returns a reference to the matrix of individual column polynomials.
    pub fn data(&self) -> &ColMatrix<E> {
        &self.data
    }

    /// Transforms this composition polynomial into a vector of individual column polynomials.
    pub fn into_columns(self) -> Vec<Vec<E>> {
        self.data.into_columns()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Splits polynomial coefficients into the specified number of columns. The coefficients are split
/// in such a way that each resulting column has the same degree. For example, a polynomial
/// a * x^3 + b * x^2 + c * x + d, can be rewritten as: (c * x + d) + x^2 * (a * x + b), and then
/// the two columns will be: (c * x + d) and (a * x + b).
fn segment<E: FieldElement>(
    coefficients: Vec<E>,
    trace_len: usize,
    num_cols: usize,
) -> Vec<Vec<E>> {
    debug_assert!(degree_of(&coefficients) < trace_len * num_cols);

    coefficients
        .chunks(trace_len)
        .take(num_cols)
        .map(|slice| slice.to_vec())
        .collect()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    use math::fields::f128::BaseElement;
    use utils::collections::Vec;

    #[test]
    fn segment() {
        let values = (0u128..16).map(BaseElement::new).collect::<Vec<_>>();
        let actual = super::segment(values, 4, 4);

        #[rustfmt::skip]
        let expected = vec![
            vec![BaseElement::new(0), BaseElement::new(1), BaseElement::new(2), BaseElement::new(3)],
            vec![BaseElement::new(4), BaseElement::new(5), BaseElement::new(6), BaseElement::new(7)],
            vec![BaseElement::new(8), BaseElement::new(9), BaseElement::new(10), BaseElement::new(11)],
            vec![BaseElement::new(12), BaseElement::new(13), BaseElement::new(14), BaseElement::new(15)],
        ];

        assert_eq!(expected, actual)
    }
}
