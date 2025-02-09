// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

#[cfg(debug_assertions)]
use air::TransitionConstraints;
#[cfg(debug_assertions)]
use math::fft;
use math::{batch_inversion, FieldElement, StarkField};
#[cfg(feature = "concurrent")]
use utils::iterators::*;
use utils::{batch_iter_mut, iter_mut, uninit_vector};

use super::{ConstraintDivisor, StarkDomain};

// CONSTANTS
// ================================================================================================

const MIN_FRAGMENT_SIZE: usize = 16;

// CONSTRAINT EVALUATION TABLE
// ================================================================================================

pub struct ConstraintEvaluationTable<'a, E: FieldElement> {
    evaluations: Vec<Vec<E>>,
    divisors: Vec<ConstraintDivisor<E::BaseField>>,
    domain: &'a StarkDomain<E::BaseField>,

    #[cfg(debug_assertions)]
    main_transition_evaluations: Vec<Vec<E::BaseField>>,
    #[cfg(debug_assertions)]
    aux_transition_evaluations: Vec<Vec<E>>,
    #[cfg(debug_assertions)]
    expected_transition_degrees: Vec<usize>,
}

impl<'a, E: FieldElement> ConstraintEvaluationTable<'a, E> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new constraint evaluation table with number of columns equal to the number of
    /// specified divisors, and number of rows equal to the size of constraint evaluation domain.
    #[cfg(not(debug_assertions))]
    pub fn new(
        domain: &'a StarkDomain<E::BaseField>,
        divisors: Vec<ConstraintDivisor<E::BaseField>>,
    ) -> Self {
        let num_columns = divisors.len();
        let num_rows = domain.ce_domain_size();
        ConstraintEvaluationTable {
            evaluations: uninit_matrix(num_columns, num_rows),
            divisors,
            domain,
        }
    }

    /// Similar to the as above constructor but used in debug mode. In debug mode we also want
    /// to keep track of all evaluated transition constraints so that we can verify that their
    /// expected degrees match their actual degrees.
    #[cfg(debug_assertions)]
    pub fn new(
        domain: &'a StarkDomain<E::BaseField>,
        divisors: Vec<ConstraintDivisor<E::BaseField>>,
        transition_constraints: &TransitionConstraints<E>,
    ) -> Self {
        let num_columns = divisors.len();
        let num_rows = domain.ce_domain_size();
        let num_tm_columns = transition_constraints.num_main_constraints();
        let num_ta_columns = transition_constraints.num_aux_constraints();

        // collect expected degrees for all transition constraints to compare them against actual
        // degrees; we do this in debug mode only because this comparison is expensive
        let expected_transition_degrees =
            build_transition_constraint_degrees(transition_constraints, domain.trace_length());

        ConstraintEvaluationTable {
            evaluations: uninit_matrix(num_columns, num_rows),
            divisors,
            domain,
            main_transition_evaluations: uninit_matrix(num_tm_columns, num_rows),
            aux_transition_evaluations: uninit_matrix(num_ta_columns, num_rows),
            expected_transition_degrees,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of rows in this table. This is the same as the size of the constraint
    /// evaluation domain.
    pub fn num_rows(&self) -> usize {
        self.evaluations[0].len()
    }

    /// Returns number of columns in this table.
    ///
    /// The first column always contains the value of combined transition constraint evaluations;
    /// the remaining columns contain values of assertion constraint evaluations combined based on
    /// common divisors.
    #[allow(dead_code)]
    pub fn num_columns(&self) -> usize {
        self.evaluations.len()
    }

    // TABLE FRAGMENTS
    // --------------------------------------------------------------------------------------------

    /// Break the table into the number of specified fragments. All fragments can be updated
    /// independently - e.g. in different threads.
    pub fn fragments(&mut self, num_fragments: usize) -> Vec<EvaluationTableFragment<E>> {
        let fragment_size = self.num_rows() / num_fragments;
        assert!(
            fragment_size >= MIN_FRAGMENT_SIZE,
            "fragment size must be at least {MIN_FRAGMENT_SIZE}, but was {fragment_size}"
        );

        // break evaluations into fragments
        let evaluation_data = make_fragments(&mut self.evaluations, num_fragments);

        #[cfg(debug_assertions)]
        let result = {
            // in debug mode, also break individual transition evaluations into fragments
            let tm_evaluation_data =
                make_fragments(&mut self.main_transition_evaluations, num_fragments);
            let ta_evaluation_data =
                make_fragments(&mut self.aux_transition_evaluations, num_fragments);

            evaluation_data
                .into_iter()
                .zip(tm_evaluation_data)
                .zip(ta_evaluation_data)
                .enumerate()
                .map(|(i, ((evaluations, tm_evaluations), ta_evaluations))| {
                    EvaluationTableFragment {
                        offset: i * fragment_size,
                        evaluations,
                        tm_evaluations,
                        ta_evaluations,
                    }
                })
                .collect()
        };

        #[cfg(not(debug_assertions))]
        let result = evaluation_data
            .into_iter()
            .enumerate()
            .map(|(i, evaluations)| EvaluationTableFragment {
                offset: i * fragment_size,
                evaluations,
            })
            .collect();

        result
    }

    // CONSTRAINT COMPOSITION
    // --------------------------------------------------------------------------------------------
    /// Divides constraint evaluation columns by their respective divisor (in evaluation form) and
    /// combines the results into a single column.
    pub fn combine(self) -> Vec<E> {
        // allocate memory for the combined polynomial
        let mut combined_poly = vec![E::ZERO; self.num_rows()];

        // iterate over all columns of the constraint evaluation table, divide each column
        // by the evaluations of its corresponding divisor, and add all resulting evaluations
        // together into a single vector
        for (column, divisor) in self.evaluations.into_iter().zip(self.divisors.iter()) {
            // divide the column by the divisor and accumulate the result into combined_poly
            acc_column(column, divisor, self.domain, &mut combined_poly);
        }

        combined_poly
    }

    // DEBUG HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(debug_assertions)]
    pub fn validate_transition_degrees(&mut self) {
        // evaluate transition constraint divisor (which is assumed to be the first one in the
        // divisor list) over the constraint evaluation domain. this is used later to compute
        // actual degrees of transition constraint evaluations.
        let div_values = evaluate_divisor::<E::BaseField>(
            &self.divisors[0],
            self.num_rows(),
            self.domain.offset(),
        );

        // collect actual degrees for all transition constraints by interpolating saved
        // constraint evaluations into polynomials and checking their degree; also
        // determine max transition constraint degree
        let mut actual_degrees = Vec::with_capacity(self.expected_transition_degrees.len());
        let mut max_degree = 0;
        let inv_twiddles = fft::get_inv_twiddles::<E::BaseField>(self.num_rows());

        // first process transition constraint evaluations for the main trace segment
        for evaluations in self.main_transition_evaluations.iter() {
            let degree = get_transition_poly_degree(evaluations, &inv_twiddles, &div_values);
            actual_degrees.push(degree);
            max_degree = core::cmp::max(max_degree, degree);
        }

        // then process transition constraint evaluations for the auxiliary trace segment
        for evaluations in self.aux_transition_evaluations.iter() {
            let degree = get_transition_poly_degree(evaluations, &inv_twiddles, &div_values);
            actual_degrees.push(degree);
            max_degree = core::cmp::max(max_degree, degree);
        }

        // make sure expected and actual degrees are equal
        assert_eq!(
            self.expected_transition_degrees, actual_degrees,
            "transition constraint degrees didn't match\nexpected: {:>3?}\nactual:   {:>3?}",
            self.expected_transition_degrees, actual_degrees
        );

        // make sure evaluation domain size does not exceed the size required by max degree
        let expected_domain_size =
            core::cmp::max(max_degree, self.domain.trace_length() + 1).next_power_of_two();
        assert_eq!(
            expected_domain_size,
            self.num_rows(),
            "incorrect constraint evaluation domain size; expected {}, but was {}",
            expected_domain_size,
            self.num_rows()
        );
    }
}

// TABLE FRAGMENTS
// ================================================================================================

pub struct EvaluationTableFragment<'a, E: FieldElement> {
    offset: usize,
    evaluations: Vec<&'a mut [E]>,

    #[cfg(debug_assertions)]
    tm_evaluations: Vec<&'a mut [E::BaseField]>,
    #[cfg(debug_assertions)]
    ta_evaluations: Vec<&'a mut [E]>,
}

impl<E: FieldElement> EvaluationTableFragment<'_, E> {
    /// Returns the row at which the fragment starts.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of evaluation rows in the fragment.
    pub fn num_rows(&self) -> usize {
        self.evaluations[0].len()
    }

    /// Returns the number of columns in every evaluation row.
    pub fn num_columns(&self) -> usize {
        self.evaluations.len()
    }

    /// Updates a single row in the fragment with provided data.
    pub fn update_row(&mut self, row_idx: usize, row_data: &[E]) {
        for (column, &value) in self.evaluations.iter_mut().zip(row_data) {
            column[row_idx] = value;
        }
    }

    /// Updates transition evaluations row with the provided data; available only in debug mode.
    #[cfg(debug_assertions)]
    pub fn update_transition_evaluations(
        &mut self,
        row_idx: usize,
        main_evaluations: &[E::BaseField],
        aux_evaluations: &[E],
    ) {
        for (column, &value) in self.tm_evaluations.iter_mut().zip(main_evaluations) {
            column[row_idx] = value;
        }
        for (column, &value) in self.ta_evaluations.iter_mut().zip(aux_evaluations) {
            column[row_idx] = value;
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Allocates memory for a two-dimensional data structure without initializing it.
fn uninit_matrix<E: FieldElement>(num_cols: usize, num_rows: usize) -> Vec<Vec<E>> {
    unsafe { (0..num_cols).map(|_| uninit_vector(num_rows)).collect() }
}

/// Breaks the source data into a mutable set of fragments such that each fragment has the same
/// number of columns as the source data, and the number of rows equal to `num_fragments`
/// parameter.
///
/// If the source data is empty, the returned vector will contain number of empty vectors equal
/// to `num_fragments` parameter.
fn make_fragments<E: FieldElement>(
    source: &mut [Vec<E>],
    num_fragments: usize,
) -> Vec<Vec<&mut [E]>> {
    let mut result = (0..num_fragments).map(|_| Vec::new()).collect::<Vec<_>>();
    if !source.is_empty() {
        let fragment_size = source[0].len() / num_fragments;
        source.iter_mut().for_each(|column| {
            for (i, fragment) in column.chunks_mut(fragment_size).enumerate() {
                result[i].push(fragment);
            }
        });
    }
    result
}

#[allow(clippy::many_single_char_names)]
fn acc_column<E: FieldElement>(
    column: Vec<E>,
    divisor: &ConstraintDivisor<E::BaseField>,
    domain: &StarkDomain<E::BaseField>,
    result: &mut [E],
) {
    let numerator = divisor.numerator();
    assert_eq!(numerator.len(), 1, "complex divisors are not yet supported");

    // compute inverse evaluations of the divisor's numerator, which has the form (x^a - b)
    let z = get_inv_evaluation(divisor, domain);

    // divide column values by the divisor; for boundary constraints this computed simply as
    // multiplication of column value by the inverse of divisor numerator; for transition
    // constraints, it is computed similarly, but the result is also multiplied by the divisor's
    // denominator (exclusion point).
    if divisor.exemptions().is_empty() {
        // the column represents merged evaluations of boundary constraints, and divisor has the
        // form of (x^a - b); thus to divide the column by the divisor, we compute: value * z,
        // where z = 1 / (x^a - 1) and has already been computed above.
        iter_mut!(result, 1024)
            .zip(column)
            .enumerate()
            .for_each(|(i, (acc_value, value))| {
                // determine which value of z corresponds to the current domain point
                let z = z[i % z.len()];
                // compute value * z and add it to the result
                *acc_value += value.mul_base(z);
            });
    } else {
        // the column represents merged evaluations of transition constraints, and divisor has the
        // form of (x^a - 1) / e(x), where e(x) describes the exemption points; thus, to divide
        // the column by the divisor, we compute: value * e(x) * z, where z = 1 / (x^a - 1) and has
        // already been computed above.
        batch_iter_mut!(
            result,
            128, // min batch size
            |batch: &mut [E], batch_offset: usize| {
                for (i, acc_value) in batch.iter_mut().enumerate() {
                    // compute value of e(x) and compute next value of x
                    let x = domain.get_ce_x_at(batch_offset + i);
                    let e = divisor.evaluate_exemptions_at(x);
                    // determine which value of z corresponds to the current domain point
                    let z = z[i % z.len()];
                    // compute value * e(x) * z and add it to the result
                    *acc_value += column[batch_offset + i].mul_base(z * e);
                }
            }
        );
    }
}

/// Computes evaluations of the divisor's numerator over the domain of the specified size and
/// offset.
fn get_inv_evaluation<B: StarkField>(
    divisor: &ConstraintDivisor<B>,
    domain: &StarkDomain<B>,
) -> Vec<B> {
    let numerator = divisor.numerator();
    let a = numerator[0].0 as u64; // numerator degree
    let b = numerator[0].1;

    // this guarantees that we can use get_ce_x_power_at() below but limits execution trace length
    // to be at most 2^32. in the future, we should revisit this to allow execution traces of
    // greater length.
    assert!(
        a <= u32::MAX as u64,
        "constraint divisor numerator degree cannot exceed {}, but was {}",
        u32::MAX,
        a
    );

    let n = domain.ce_domain_size() / a as usize;
    let domain_offset_exp = domain.offset().exp(a.into());

    // compute x^a - b for all x
    let mut evaluations = unsafe { uninit_vector(n) };
    batch_iter_mut!(
        &mut evaluations,
        128, // min batch size
        |batch: &mut [B], batch_offset: usize| {
            for (i, evaluation) in batch.iter_mut().enumerate() {
                let x = domain.get_ce_x_power_at(batch_offset + i, a, domain_offset_exp);
                *evaluation = x - b;
            }
        }
    );

    // compute 1 / (x^a - b)
    batch_inversion(&evaluations)
}

// DEBUG HELPERS
// ================================================================================================

/// Returns evaluation degrees of all transition constraints.
///
/// An evaluation degree is defined as degree of transition constraints in the context of a given
/// execution trace accounting for constraint divisor degree. For most constraints, this degree is
/// computed as `([trace_length - 1] * [constraint degree]) - [divisor degree]`. However, for
/// constraints which rely on periodic columns this computation is slightly more complex.
///
/// The general idea is that evaluation degree is the degree of rational function `C(x) / z(x)`,
/// where `C(x)` is the constraint polynomial and `z(x)` is the divisor polynomial.
#[cfg(debug_assertions)]
fn build_transition_constraint_degrees<E: FieldElement>(
    constraints: &TransitionConstraints<E>,
    trace_length: usize,
) -> Vec<usize> {
    let mut result = Vec::new();

    for degree in constraints.main_constraint_degrees() {
        result.push(degree.get_evaluation_degree(trace_length) - constraints.divisor().degree())
    }

    for degree in constraints.aux_constraint_degrees() {
        result.push(degree.get_evaluation_degree(trace_length) - constraints.divisor().degree())
    }

    result
}

/// Computes the actual degree of a transition polynomial described by the provided evaluations.
///
/// The degree is computed as follows:
/// - First, we divide the polynomial evaluations by the evaluations of transition constraint
///   divisor (`div_values`). This is needed because it is possible for the numerator portions of
///   transition constraints to have a degree which is larger than the size of the evaluation domain
///   (and thus, interpolating the numerator would yield an incorrect result). However, once the
///   divisor values are divided out, the degree of the resulting polynomial should be smaller than
///   the size of the evaluation domain, and thus, we can interpolate safely.
/// - Then, we interpolate the polynomial over the domain specified by `inv_twiddles`.
/// - And finally, we get the degree from the interpolated polynomial.
#[cfg(debug_assertions)]
fn get_transition_poly_degree<E: FieldElement>(
    evaluations: &[E],
    inv_twiddles: &[E::BaseField],
    div_values: &[E::BaseField],
) -> usize {
    let mut evaluations = evaluations
        .iter()
        .zip(div_values)
        .map(|(&c, &d)| c / E::from(d))
        .collect::<Vec<_>>();
    fft::interpolate_poly(&mut evaluations, inv_twiddles);
    math::polynom::degree_of(&evaluations)
}

/// Evaluates constraint divisor over the specified domain. This is similar to [get_inv_evaluation]
/// function above but uses a more straight-forward but less efficient evaluation methodology and
/// also does not invert the results.
#[cfg(debug_assertions)]
fn evaluate_divisor<E: FieldElement>(
    divisor: &ConstraintDivisor<E::BaseField>,
    domain_size: usize,
    domain_offset: E::BaseField,
) -> Vec<E> {
    let g = E::BaseField::get_root_of_unity(domain_size.trailing_zeros());
    let domain = math::get_power_series_with_offset(g, domain_offset, domain_size);
    domain.into_iter().map(|x| E::from(divisor.evaluate_at(x))).collect()
}
