// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ConstraintPoly, StarkDomain};
use common::{errors::ProverError, ConstraintDivisor};
use math::{
    fft,
    field::{FieldElement, StarkField},
    utils::{batch_inversion, get_power_series_with_offset},
};
use utils::uninit_vector;

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// CONSTANTS
// ================================================================================================

#[cfg(feature = "concurrent")]
const MIN_FRAGMENT_SIZE: usize = 256;

// CONSTRAINT EVALUATION TABLE
// ================================================================================================

pub struct ConstraintEvaluationTable<B: StarkField, E: FieldElement + From<B>> {
    evaluations: Vec<Vec<E>>,
    divisors: Vec<ConstraintDivisor<B>>,
    domain_offset: B,
    trace_length: usize,

    #[cfg(debug_assertions)]
    t_evaluations: Vec<Vec<B>>,
    #[cfg(debug_assertions)]
    t_expected_degrees: Vec<usize>,
}

impl<B: StarkField, E: FieldElement + From<B>> ConstraintEvaluationTable<B, E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new constraint evaluation table with number of columns equal to the number of
    /// specified divisors, and number of rows equal to the size of constraint evaluation domain.
    #[cfg(not(debug_assertions))]
    pub fn new(domain: &StarkDomain<B>, divisors: Vec<ConstraintDivisor<B>>) -> Self {
        let num_columns = divisors.len();
        let num_rows = domain.ce_domain_size();
        ConstraintEvaluationTable {
            evaluations: (0..num_columns).map(|_| uninit_vector(num_rows)).collect(),
            divisors,
            domain_offset: domain.offset(),
            trace_length: domain.trace_length(),
        }
    }

    /// Similar to the as above constructor but used in debug mode. In debug mode we also want
    /// to keep track of all evaluated transition constraints so that we can verify that their
    /// expected degrees match their actual degrees.
    #[cfg(debug_assertions)]
    pub fn new(
        domain: &StarkDomain<B>,
        divisors: Vec<ConstraintDivisor<B>>,
        transition_constraint_degrees: Vec<usize>,
    ) -> Self {
        let num_columns = divisors.len();
        let num_rows = domain.ce_domain_size();
        let num_t_columns = transition_constraint_degrees.len();
        ConstraintEvaluationTable {
            evaluations: (0..num_columns).map(|_| uninit_vector(num_rows)).collect(),
            divisors,
            domain_offset: domain.offset(),
            trace_length: domain.trace_length(),
            t_evaluations: (0..num_t_columns)
                .map(|_| uninit_vector(num_rows))
                .collect(),
            t_expected_degrees: transition_constraint_degrees,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of rows in this table. This is the same as the size of the constraint
    /// evaluation domain.
    pub fn num_rows(&self) -> usize {
        self.evaluations[0].len()
    }

    /// Returns number of columns in this table. The first column always contains the value of
    /// combined transition constraint evaluations; the remaining columns contain values of
    /// assertion constraint evaluations combined based on common divisors.
    pub fn num_columns(&self) -> usize {
        self.evaluations.len()
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates a single row in the table with provided data.
    pub fn update_row(&mut self, row_idx: usize, row_data: &[E]) {
        for (column, &value) in self.evaluations.iter_mut().zip(row_data) {
            column[row_idx] = value;
        }
    }

    /// In concurrent mode, we break the table into fragments and update each fragment in
    /// separate threads.
    #[cfg(feature = "concurrent")]
    pub fn fragments(&mut self, num_fragments: usize) -> Vec<TableFragment<E>> {
        let fragment_size = self.num_rows() / num_fragments;
        assert!(
            fragment_size >= MIN_FRAGMENT_SIZE,
            "fragment size must be at least {}, but was {}",
            MIN_FRAGMENT_SIZE,
            fragment_size
        );

        let mut fragment_data = (0..num_fragments).map(|_| Vec::new()).collect::<Vec<_>>();
        self.evaluations.iter_mut().for_each(|column| {
            for (i, fragment) in column.chunks_mut(fragment_size).enumerate() {
                fragment_data[i].push(fragment);
            }
        });

        fragment_data
            .into_iter()
            .enumerate()
            .map(|(i, data)| TableFragment {
                offset: i * fragment_size,
                data,
            })
            .collect()
    }

    // CONSTRAINT COMPOSITION
    // --------------------------------------------------------------------------------------------
    /// Interpolates all constraint evaluations into polynomials, divides them by their respective
    /// divisors, and combines the results into a single polynomial
    pub fn into_poly(self) -> Result<ConstraintPoly<E>, ProverError> {
        let constraint_poly_degree = self.constraint_poly_degree();
        let domain_offset = self.domain_offset;

        // allocate memory for the combined polynomial
        let mut combined_poly = E::zeroed_vector(self.num_rows());

        // iterate over all columns of the constraint evaluation table, divide each column
        // by the evaluations of its corresponding divisor, and add all resulting evaluations
        // together into a single vector
        for (column, divisor) in self.evaluations.into_iter().zip(self.divisors.iter()) {
            // in debug mode, make sure post-division degree of each column matches the expected
            // degree
            #[cfg(debug_assertions)]
            validate_column_degree(&column, &divisor, domain_offset, constraint_poly_degree)?;

            // divide the column by the divisor and accumulate the result into combined_poly
            acc_column(column, divisor, self.domain_offset, &mut combined_poly);
        }

        // at this point, combined_poly contains evaluations of the combined constraint polynomial;
        // we interpolate this polynomial to transform it into coefficient form.
        let inv_twiddles = fft::get_inv_twiddles::<B>(combined_poly.len());
        fft::interpolate_poly_with_offset(&mut combined_poly, &inv_twiddles, domain_offset);

        Ok(ConstraintPoly::new(combined_poly, constraint_poly_degree))
    }

    // DEBUG HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(all(debug_assertions, not(feature = "concurrent")))]
    pub fn update_transition_evaluations(&mut self, row_idx: usize, row_data: &[B]) {
        for (column, &value) in self.t_evaluations.iter_mut().zip(row_data) {
            column[row_idx] = value;
        }
    }

    #[cfg(debug_assertions)]
    pub fn validate_transition_degrees(&mut self) {
        // collect actual degrees for all transition constraints by interpolating saved
        // constraint evaluations into polynomials and checking their degree; also
        // determine max transition constraint degree
        let mut actual_degrees = Vec::with_capacity(self.t_expected_degrees.len());
        let mut max_degree = 0;
        let inv_twiddles = fft::get_inv_twiddles::<B>(self.num_rows());
        for evaluations in self.t_evaluations.iter() {
            let mut poly = evaluations.clone();
            fft::interpolate_poly(&mut poly, &inv_twiddles);
            let degree = math::polynom::degree_of(&poly);
            actual_degrees.push(degree);

            max_degree = std::cmp::max(max_degree, degree);
        }

        // make sure expected and actual degrees are equal
        if self.t_expected_degrees != actual_degrees {
            panic!(
                "transition constraint degrees didn't match\nexpected: {:>3?}\nactual:   {:>3?}",
                self.t_expected_degrees, actual_degrees
            );
        }

        // make sure evaluation domain size does not exceed the size required by max degree
        let expected_domain_size =
            std::cmp::max(max_degree, self.trace_length + 1).next_power_of_two();
        if expected_domain_size != self.num_rows() {
            panic!(
                "incorrect constraint evaluation domain size; expected {}, actual: {}",
                expected_domain_size,
                self.num_rows()
            );
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Computes expected degree of composed constraint polynomial.
    fn constraint_poly_degree(&self) -> usize {
        self.num_rows() - self.trace_length
    }
}

// TABLE FRAGMENTS
// ================================================================================================

#[cfg(feature = "concurrent")]
pub struct TableFragment<'a, E: FieldElement> {
    offset: usize,
    data: Vec<&'a mut [E]>,
}

#[cfg(feature = "concurrent")]
impl<'a, E: FieldElement> TableFragment<'a, E> {
    /// Returns the row at which the fragment starts.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of evaluation rows in the fragment.
    pub fn num_rows(&self) -> usize {
        self.data[0].len()
    }

    /// Returns the number of columns in every evaluation row.
    #[allow(dead_code)]
    pub fn num_columns(&self) -> usize {
        self.data.len()
    }

    /// Updates a single row in the fragment with provided data.
    pub fn update_row(&mut self, row_idx: usize, row_data: &[E]) {
        for (column, &value) in self.data.iter_mut().zip(row_data) {
            column[row_idx] = value;
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[allow(clippy::many_single_char_names)]
fn acc_column<B: StarkField, E: FieldElement + From<B>>(
    column: Vec<E>,
    divisor: &ConstraintDivisor<B>,
    domain_offset: B,
    result: &mut [E],
) {
    let numerator = divisor.numerator();
    assert!(
        numerator.len() == 1,
        "complex divisors are not yet supported"
    );
    assert!(
        divisor.exclude().len() <= 1,
        "multiple exclusion points are not yet supported"
    );

    // compute evaluations of the divisor's numerator, which has the form (x^a - b)
    let domain_size = column.len();
    let z = get_inv_evaluation(divisor, domain_size, domain_offset);

    if divisor.exclude().is_empty() {
        // the column represents merged evaluations of boundary constraints, and divisor has the
        // form of (x^a - b); thus to divide the column by the divisor, we compute: value * z,
        // where z = 1 / (x^a - 1) and has already been computed above.

        for (i, (result, value)) in result.iter_mut().zip(column).enumerate() {
            // determine which value of z corresponds to the current domain point
            let z = E::from(z[i % z.len()]);
            // compute value * z and add it to the result
            *result += value * z;
        }
    } else {
        // the column represents merged evaluations of transition constraints, and divisor has the
        // form of (x^a - 1) / (x - b); thus, to divide the column by the divisor, we compute:
        // value * (x - b) * z, where z = 1 / (x^a - 1) and has already been computed above.

        // set up variables for computing x at every point in the domain
        let g = B::get_root_of_unity(domain_size.trailing_zeros());
        let mut x = domain_offset;
        let b = divisor.exclude()[0];

        for (i, (result, value)) in result.iter_mut().zip(column).enumerate() {
            // compute value of (x - b) and compute next value of x
            let e = x - b;
            x *= g;
            // determine which value of z corresponds to the current domain point
            let z = z[i % z.len()];
            // compute value * (x - b) * z and add it to the result
            *result += value * E::from(z * e);
        }
    }
}

/// Computes evaluations of the divisor's numerator over the domain of the specified size and offset.
fn get_inv_evaluation<B: StarkField>(
    divisor: &ConstraintDivisor<B>,
    domain_size: usize,
    domain_offset: B,
) -> Vec<B> {
    let numerator = divisor.numerator();
    let a = numerator[0].0 as u32; // numerator degree
    let b = numerator[0].1;

    let n = domain_size / a as usize;

    let g = B::get_root_of_unity(domain_size.trailing_zeros()).exp(a.into());
    let offset = domain_offset.exp(a.into());

    let result = get_power_series_with_offset(g, offset, n);
    let result = result.into_iter().map(|x| x - b).collect::<Vec<_>>();
    batch_inversion(&result)
}

/// makes sure that the post-division degree of the polynomial matches the expected degree
#[cfg(debug_assertions)]
fn validate_column_degree<B: StarkField, E: FieldElement + From<B>>(
    column: &[E],
    divisor: &ConstraintDivisor<B>,
    domain_offset: B,
    composition_degree: usize,
) -> Result<(), ProverError> {
    // convert the polynomial into coefficient form by interpolating the evaluations
    // over the evaluation domain
    let mut column = column.to_vec();
    let inv_twiddles = fft::get_inv_twiddles::<B>(column.len());
    fft::interpolate_poly_with_offset(&mut column, &inv_twiddles, domain_offset);
    let mut poly = column;

    // divide the polynomial by its divisor
    let numerator = divisor.numerator();
    let numerator = numerator[0];
    let degree = numerator.0;

    if divisor.exclude().is_empty() {
        // the form of the divisor is just (x^degree - a)
        let a = E::from(numerator.1);
        math::polynom::syn_div_in_place(&mut poly, degree, a);
    } else {
        // the form of divisor is (x^degree - 1) / (x - exception)
        let exception = E::from(divisor.exclude()[0]);
        math::polynom::syn_div_in_place_with_exception(&mut poly, degree, exception);
    }

    if composition_degree != math::polynom::degree_of(&poly) {
        return Err(ProverError::MismatchedConstraintPolynomialDegree(
            composition_degree,
            math::polynom::degree_of(&poly),
        ));
    }
    Ok(())
}
