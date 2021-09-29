// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::{StarkDomain, TraceLde, TracePolyTable};
use air::TraceInfo;
use math::{fft, log2, StarkField};
use utils::{collections::Vec, iter_mut, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// TRACE TABLE
// ================================================================================================

/// TODO: add comments
pub struct TraceTable<B: StarkField>(Vec<Vec<B>>);

impl<B: StarkField> TraceTable<B> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new trace table from the list of provided columns.
    ///
    /// The provides `data` vector is expected to contain a list of equal-length columns.
    ///
    /// # Panics
    /// Panics if:
    /// * The `data` vector is empty or has over 255 columns.
    /// * Length of any of the columns is smaller than 8, greater than the biggest multiplicative
    ///   subgroup in the field `B`, or is not a power of two.
    /// * Not all columns have identical lengths.
    pub fn new(data: Vec<Vec<B>>) -> Self {
        assert!(
            !data.is_empty(),
            "trace table must consist of at least one column"
        );
        assert!(
            data.len() <= TraceInfo::MAX_TRACE_WIDTH,
            "trace table width cannot be greater than {}, but was {}",
            TraceInfo::MAX_TRACE_WIDTH,
            data.len()
        );
        let trace_length = data[0].len();
        assert!(
            trace_length >= TraceInfo::MIN_TRACE_LENGTH,
            "trace table must be at lest {} steps long, but was {}",
            TraceInfo::MIN_TRACE_LENGTH,
            trace_length
        );
        assert!(
            trace_length.is_power_of_two(),
            "trace table length must be a power of 2"
        );
        assert!(
            log2(trace_length) as u32 <= B::TWO_ADICITY,
            "trace table length cannot exceed 2^{} steps, but was 2^{}",
            B::TWO_ADICITY,
            log2(trace_length)
        );
        for column in data.iter() {
            assert_eq!(
                column.len(),
                trace_length,
                "all columns must have the same length"
            );
        }

        Self(data)
    }

    /// Creates a new trace table of the specified width and length.
    ///
    /// This allocates all the required memory for the trace, but does not initialize it. It is
    /// expected that the trace will be subsequently filled by the user.
    ///
    /// # Safety
    /// Since the allocated memory is un-initialized, not filling the table in its entirety is
    /// will result in undefined behavior.
    ///
    /// # Panics
    /// Panics if:
    /// * `width` is zero or greater than 255.
    /// * `length` is smaller than 8, greater than biggest multiplicative subgroup in the field
    ///   `B`, or is not a power of two.
    pub unsafe fn new_blank(width: usize, length: usize) -> Self {
        let data = (0..width).map(|_| uninit_vector(length)).collect();
        Self::new(data)
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates a value in a single cell of the table.
    ///
    /// Specifically, the value in the specified `column` and the specified `step` is set to the
    /// provide `value`.
    ///
    /// # Panics
    /// Panics if either `column` or `step` are out of bounds for this table.
    pub fn set(&mut self, column: usize, step: usize, value: B) {
        self.0[column][step] = value;
    }

    /// Updates a single row in the table with provided data.
    pub fn update_row(&mut self, step: usize, state: &[B]) {
        for (column, &value) in self.0.iter_mut().zip(state) {
            column[step] = value;
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in this table.
    pub fn width(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of states in this table.
    pub fn length(&self) -> usize {
        self.0[0].len()
    }

    /// Returns value of the cell in specified `column` at the specified `step`.
    pub fn get(&self, column: usize, step: usize) -> B {
        self.0[column][step]
    }

    /// Returns the entire column at the specified index.
    pub fn get_column(&self, col_idx: usize) -> &[B] {
        &self.0[col_idx]
    }

    /// Returns a copy of the entire table row at the specified step.
    pub fn get_row(&self, step: usize) -> Vec<B> {
        let mut result = B::zeroed_vector(self.width());
        self.read_row_into(step, &mut result);
        result
    }

    /// Reads a single row of this table at the specified `step` into the specified `target`.
    pub fn read_row_into(&self, step: usize, target: &mut [B]) {
        for (i, column) in self.0.iter().enumerate() {
            target[i] = column[step];
        }
    }

    // LOW-DEGREE EXTENSION
    // --------------------------------------------------------------------------------------------
    /// Extends all columns of this table to the length of the LDE domain.
    ///
    /// The extension is done by first interpolating each column into a polynomial over the trace
    /// domain, and then evaluating the polynomial over the LDE domain.
    pub fn extend(mut self, domain: &StarkDomain<B>) -> (TraceLde<B>, TracePolyTable<B>) {
        assert_eq!(
            self.length(),
            domain.trace_length(),
            "inconsistent trace length"
        );
        // build and cache trace twiddles for FFT interpolation; we do it here so that we
        // don't have to rebuild these twiddles for every column.
        let inv_twiddles = fft::get_inv_twiddles::<B>(self.length());

        // extend all columns; the extension procedure first interpolates columns into polynomials
        // (in-place), then evaluates these polynomials over a larger domain, and then returns
        // extended evaluations.
        let extended_trace = iter_mut!(self.0)
            .map(|column| extend_column(column, domain, &inv_twiddles))
            .collect();

        (
            TraceLde::new(extended_trace, domain.trace_to_lde_blowup()),
            TracePolyTable::new(self.0),
        )
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[inline(always)]
fn extend_column<B: StarkField>(
    trace: &mut [B],
    domain: &StarkDomain<B>,
    inv_twiddles: &[B],
) -> Vec<B> {
    let domain_offset = domain.offset();
    let twiddles = domain.trace_twiddles();
    let blowup_factor = domain.trace_to_lde_blowup();

    // interpolate column into a polynomial; we do this over the un-shifted trace_domain
    fft::interpolate_poly(trace, inv_twiddles);

    // evaluate the polynomial over extended domain; the domain may be shifted by the
    // domain_offset
    fft::evaluate_poly_with_offset(trace, twiddles, domain_offset, blowup_factor)
}
