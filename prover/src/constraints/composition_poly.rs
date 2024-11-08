// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use air::ZkParameters;
use math::{fft, polynom, FieldElement};
use rand::{Rng, RngCore};

use super::{ColMatrix, StarkDomain};

// CONSTRAINT COMPOSITION POLYNOMIAL TRACE
// ================================================================================================

/// Represents merged evaluations of all constraint evaluations.
pub struct CompositionPolyTrace<E>(Vec<E>);

impl<E: FieldElement> CompositionPolyTrace<E> {
    /// Returns a new instance of [CompositionPolyTrace] instantiated from the provided evaluations.
    ///
    /// # Panics
    /// Panics if the number of evaluations is not a power of 2.
    pub fn new(evaluations: Vec<E>) -> Self {
        assert!(
            evaluations.len().is_power_of_two(),
            "length of composition polynomial trace must be a power of 2, but was {}",
            evaluations.len(),
        );

        Self(evaluations)
    }

    /// Returns the number of evaluations in this trace.
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }

    /// Returns the internal vector representing this trace.
    pub fn into_inner(self) -> Vec<E> {
        self.0
    }
}

// CONSTRAINT COMPOSITION POLYNOMIAL
// ================================================================================================
/// A composition polynomial split into columns with each column being of length equal to trace_length.
///
/// For example, if the composition polynomial has degree 2N - 1, where N is the trace length,
/// it will be stored as two columns of size N (each of degree N - 1).
///
/// When zero-knowledge is enabled, the composition polynomial is split into segment polynomials
/// such that each segment polynomial's degree is small enough to accommodate adding a randomizer
/// polynomial without the degree of the resulting ranomized segment polynomial exceeding
/// `domain.trace_length()`.
pub struct CompositionPoly<E: FieldElement> {
    data: ColMatrix<E>,
}

impl<E: FieldElement> CompositionPoly<E> {
    /// Returns a new composition polynomial.
    pub fn new<R: RngCore>(
        composition_trace: CompositionPolyTrace<E>,
        domain: &StarkDomain<E::BaseField>,
        num_cols: usize,
        zk_parameters: Option<ZkParameters>,
        prng: &mut R,
    ) -> Self {
        assert!(
            domain.trace_length() < composition_trace.num_rows(),
            "trace length must be smaller than length of composition polynomial trace"
        );

        let mut trace = composition_trace.into_inner();

        // at this point, combined_poly contains evaluations of the combined constraint polynomial;
        // we interpolate this polynomial to transform it into coefficient form.
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(trace.len());
        fft::interpolate_poly_with_offset(&mut trace, &inv_twiddles, domain.offset());

        // compute the segment quotient polynomials
        let quotient_degree = polynom::degree_of(&trace);
        let degree_chunked_quotient = if zk_parameters.is_some() {
            (quotient_degree + 1).div_ceil(num_cols)
        } else {
            domain.trace_length()
        };
        let polys = segment(trace, degree_chunked_quotient, num_cols);
        let mut polys = complement_to(polys, domain.trace_length(), prng);

        // generate a randomizer polynomial for FRI
        if zk_parameters.is_some() {
            let extended_len = polys[0].len();
            let mut zk_col = vec![E::ZERO; extended_len];

            for a in zk_col.iter_mut() {
                let bytes = prng.gen::<[u8; 32]>();
                *a = E::from_random_bytes(&bytes[..E::VALUE_SIZE])
                    .expect("failed to generate randomness");
            }
            // reduce the degree to match that of the DEEP composition polynomial
            zk_col[extended_len - 1] = E::ZERO;
            polys.push(zk_col)
        }

        CompositionPoly { data: ColMatrix::new(polys) }
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
    pub fn evaluate_at(&self, z: E, is_zk: bool) -> Vec<E> {
        self.data.evaluate_columns_at(z, is_zk)
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

/// Takes a vector of coefficients representing the segment polynomials of a given composition
/// polynomial as input, and generates coefficients of their randomized version.
///
/// The randomization technique is the one in section 4.1 in https://eprint.iacr.org/2024/1037.pdf.
fn complement_to<R: RngCore, E: FieldElement>(
    polys: Vec<Vec<E>>,
    l: usize,
    prng: &mut R,
) -> Vec<Vec<E>> {
    let mut result = vec![];

    let randomizer_poly_size = l - polys[0].len();
    let mut current_poly = vec![E::ZERO; randomizer_poly_size];
    let mut previous_poly = vec![E::ZERO; randomizer_poly_size];

    for (_, poly) in polys.iter().enumerate().take_while(|(index, _)| *index != polys.len() - 1) {
        let diff = l - poly.len();

        for eval in current_poly.iter_mut().take(diff) {
            let bytes = prng.gen::<[u8; 32]>();
            *eval = E::from_random_bytes(&bytes[..E::VALUE_SIZE])
                .expect("failed to generate randomness");
        }

        let mut res = vec![];
        res.extend_from_slice(poly);
        res.extend_from_slice(&current_poly);

        for i in 0..randomizer_poly_size {
            res[i] -= previous_poly[i];
        }

        previous_poly.copy_from_slice(&current_poly[..randomizer_poly_size]);

        result.push(res)
    }

    let poly = polys.last().unwrap();
    let mut res = vec![E::ZERO; l];
    for (i, entry) in poly.iter().enumerate() {
        res[i] = *entry;
    }
    for i in 0..randomizer_poly_size {
        res[i] -= previous_poly[i];
    }
    result.push(res);
    result
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

    use alloc::vec::Vec;

    use math::fields::f128::BaseElement;

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
