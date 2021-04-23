// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{ConstraintPoly, StarkDomain};
use common::{errors::ProverError, ConstraintDivisor};
use math::{
    fft,
    field::{FieldElement, StarkField},
    polynom,
    utils::add_in_place,
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

        // build twiddles for interpolation; these can be used to interpolate all polynomials
        let inv_twiddles = fft::get_inv_twiddles::<B>(self.num_rows());

        #[cfg(feature = "concurrent")]
        {
            let divisors = self.divisors;
            let polys = self
                .evaluations
                .into_par_iter()
                .zip(divisors.par_iter())
                .map(|(column, divisor)| {
                    apply_divisor(column, divisor, &inv_twiddles, domain_offset)
                })
                .collect::<Vec<_>>();

            for poly in polys.into_iter() {
                #[cfg(debug_assertions)]
                validate_degree(&poly, constraint_poly_degree)?;
                add_in_place(&mut combined_poly, &poly);
            }
        }

        // iterate over all columns of the constraint evaluation table
        #[cfg(not(feature = "concurrent"))]
        for (column, divisor) in self.evaluations.into_iter().zip(self.divisors.iter()) {
            let poly = apply_divisor(column, divisor, &inv_twiddles, domain_offset);
            #[cfg(debug_assertions)]
            validate_degree(&poly, constraint_poly_degree)?;
            add_in_place(&mut combined_poly, &poly);
        }

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
            let degree = polynom::degree_of(&poly);
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

fn apply_divisor<B: StarkField, E: FieldElement + From<B>>(
    mut column: Vec<E>,
    divisor: &ConstraintDivisor<B>,
    inv_twiddles: &[B],
    domain_offset: B,
) -> Vec<E> {
    let numerator = divisor.numerator();
    assert!(
        numerator.len() == 1,
        "complex divisors are not yet supported"
    );
    assert!(
        divisor.exclude().len() <= 1,
        "multiple exclusion points are not yet supported"
    );

    // convert the polynomial into coefficient form by interpolating the evaluations
    // over the evaluation domain
    fft::interpolate_poly_with_offset(&mut column, &inv_twiddles, domain_offset);
    let mut poly = column;

    // divide the polynomial by its divisor
    let numerator = numerator[0];
    let degree = numerator.0;

    if divisor.exclude().is_empty() {
        // the form of the divisor is just (x^degree - a)
        let a = E::from(numerator.1);
        polynom::syn_div_in_place(&mut poly, degree, a);
    } else {
        // the form of divisor is (x^degree - 1) / (x - exception)
        let exception = E::from(divisor.exclude()[0]);
        polynom::syn_div_in_place_with_exception(&mut poly, degree, exception);
    }

    poly
}

/// makes sure that the post-division degree of the polynomial matches the expected degree
#[cfg(debug_assertions)]
fn validate_degree<E: FieldElement>(
    poly: &[E],
    composition_degree: usize,
) -> Result<(), ProverError> {
    if composition_degree != polynom::degree_of(&poly) {
        return Err(ProverError::MismatchedConstraintPolynomialDegree(
            composition_degree,
            polynom::degree_of(&poly),
        ));
    }
    Ok(())
}
