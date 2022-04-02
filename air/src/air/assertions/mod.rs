// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::AssertionError;
use core::{
    cmp::{Ord, Ordering, PartialOrd},
    fmt::{Display, Formatter},
};
use math::FieldElement;
use utils::collections::Vec;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

const MIN_STRIDE_LENGTH: usize = 2;
const NO_STRIDE: usize = 0;

// ASSERTION
// ================================================================================================

/// An assertion made against an execution trace.
///
/// An assertion is always placed against a single column of an execution trace, but can cover
/// multiple steps and multiple values. Specifically, there are three kinds of assertions:
///
/// 1. **Single** assertion - which requires that a value in a single cell of an execution trace
///    is equal to the specified value.
/// 2. **Periodic** assertion - which requires that values in multiple cells of a single column
///   are equal to the specified value. The cells must be evenly spaced at intervals with lengths
///   equal to powers of two. For example, we can specify that values in a column must be equal
///   to 0 at steps 0, 8, 16, 24, 32 etc. Steps can also start at some offset - e.g., 1, 9, 17,
///   25, 33 is also a valid sequence of steps.
/// 3. **Sequence** assertion - which requires that multiple cells in a single column are equal
///   to the values from the provided list. The cells must be evenly spaced at intervals with
///   lengths equal to powers of two. For example, we can specify that values in a column must
///   be equal to a sequence 1, 2, 3, 4 at steps 0, 8, 16, 24. That is, value at step 0 should be
///   equal to 1, value at step 8 should be equal to 2 etc.
///
/// Note that single and periodic assertions are succinct. That is, a verifier can evaluate them
/// very efficiently. However, sequence assertions have liner complexity in the number of
/// asserted values. Though, unless many thousands of values are asserted, practical impact of
/// this linear complexity should be negligible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion<E: FieldElement> {
    pub(super) column: usize,
    pub(super) first_step: usize,
    pub(super) stride: usize,
    pub(super) values: Vec<E>,
}

impl<E: FieldElement> Assertion<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------
    /// Returns an assertion against a single cell of an execution trace.
    ///
    /// The returned assertion requires that the value in the specified `column` at the specified
    /// `step` is equal to the provided `value`.
    pub fn single(column: usize, step: usize, value: E) -> Self {
        Assertion {
            column,
            first_step: step,
            stride: NO_STRIDE,
            values: vec![value],
        }
    }

    /// Returns an single-value assertion against multiple cells of a single column.
    ///
    /// The returned assertion requires that values in the specified `column` must be equal to
    /// the specified `value` at steps which start at `first_step` and repeat in equal intervals
    /// specified by `stride`.
    ///
    /// # Panics
    /// Panics if:
    /// * `stride` is not a power of two, or is smaller than 2.
    /// * `first_step` is greater than `stride`.
    pub fn periodic(column: usize, first_step: usize, stride: usize, value: E) -> Self {
        validate_stride(stride, first_step, column);
        Assertion {
            column,
            first_step,
            stride,
            values: vec![value],
        }
    }

    /// Returns a multi-value assertion against multiple cells of a single column.
    ///
    /// The returned assertion requires that values in the specified `column` must be equal to
    /// the provided `values` at steps which start at `first_step` and repeat in equal intervals
    /// specified by `stride` until all values have been consumed.
    ///
    /// # Panics
    /// Panics if:
    /// * `stride` is not a power of two, or is smaller than 2.
    /// * `first_step` is greater than `stride`.
    /// * `values` is empty or number of values in not a power of two.
    pub fn sequence(column: usize, first_step: usize, stride: usize, values: Vec<E>) -> Self {
        validate_stride(stride, first_step, column);
        assert!(
            !values.is_empty(),
            "invalid assertion for column {}: number of asserted values must be greater than zero",
            column
        );
        assert!(
            values.len().is_power_of_two(),
            "invalid assertion for column {}: number of asserted values must be a power of two, but was {}",
            column,
            values.len()
        );
        Assertion {
            column,
            first_step,
            stride: if values.len() == 1 { NO_STRIDE } else { stride },
            values,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns index of the column against which this assertion is placed.
    pub fn column(&self) -> usize {
        self.column
    }

    /// Returns the first step of the execution trace against which this assertion is placed.
    ///
    /// For single value assertions this is equivalent to the assertion step.
    pub fn first_step(&self) -> usize {
        self.first_step
    }

    /// Returns the interval at which the assertion repeats in the execution trace.
    ///
    /// For single value assertions, this will be 0.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// Returns asserted values.
    ///
    /// For single value and periodic assertions this will be a slice containing one value.
    pub fn values(&self) -> &[E] {
        &self.values
    }

    /// Returns true if this is a single-value assertion (one value, one step).
    pub fn is_single(&self) -> bool {
        self.stride == NO_STRIDE
    }

    /// Returns true if this is a periodic assertion (one value, many steps).
    pub fn is_periodic(&self) -> bool {
        self.stride != NO_STRIDE && self.values.len() == 1
    }

    /// Returns true if this is a sequence assertion (many values, many steps).
    pub fn is_sequence(&self) -> bool {
        self.values.len() > 1
    }

    // PUBLIC METHODS
    // --------------------------------------------------------------------------------------------

    /// Checks if this assertion overlaps with the provided assertion.
    ///
    /// Overlap is defined as asserting a value for the same step in the same column.
    pub fn overlaps_with(&self, other: &Assertion<E>) -> bool {
        if self.column != other.column {
            return false;
        }
        if self.first_step == other.first_step {
            return true;
        }
        if self.stride == other.stride {
            return false;
        }

        // at this point we know that assertions are for the same column but they start
        // on different steps and also have different strides

        if self.first_step < other.first_step {
            if self.is_single() {
                return false;
            }
            if other.is_single() || self.stride < other.stride {
                (other.first_step - self.first_step) % self.stride == 0
            } else {
                false
            }
        } else {
            if other.is_single() {
                return false;
            }
            if self.is_single() || other.stride < self.stride {
                (self.first_step - other.first_step) % other.stride == 0
            } else {
                false
            }
        }
    }

    /// Panics if the assertion cannot be placed against an execution trace of the specified width.
    pub fn validate_trace_width(&self, trace_width: usize) -> Result<(), AssertionError> {
        if self.column >= trace_width {
            return Err(AssertionError::TraceWidthTooShort(self.column, trace_width));
        }
        Ok(())
    }

    /// Checks if the assertion is valid against an execution trace of the specified length.
    ///
    /// # Errors
    /// Returns an error if:
    /// * `trace_length` is not a power of two.
    /// * For single assertion, `first_step` >= `trace_length`.
    /// * For periodic assertion, `stride` > `trace_length`.
    /// * For sequence assertion, `num_values` * `stride` != `trace_length`;
    pub fn validate_trace_length(&self, trace_length: usize) -> Result<(), AssertionError> {
        if !trace_length.is_power_of_two() {
            return Err(AssertionError::TraceLengthNotPowerOfTwo(trace_length));
        }
        if self.is_single() {
            if self.first_step >= trace_length {
                return Err(AssertionError::TraceLengthTooShort(
                    (self.first_step + 1).next_power_of_two(),
                    trace_length,
                ));
            }
        } else if self.is_periodic() {
            if self.stride > trace_length {
                return Err(AssertionError::TraceLengthTooShort(
                    self.stride,
                    trace_length,
                ));
            }
        } else {
            let expected_length = self.values.len() * self.stride;
            if expected_length != trace_length {
                return Err(AssertionError::TraceLengthNotExact(
                    expected_length,
                    trace_length,
                ));
            }
        }
        Ok(())
    }

    /// Executes the provided closure for all possible instantiations of this assertions against
    /// a execution trace of the specified length.
    ///
    /// # Panics
    /// Panics if the specified trace length is not valid for this assertion.
    pub fn apply<F>(&self, trace_length: usize, mut f: F)
    where
        F: FnMut(usize, E),
    {
        self.validate_trace_length(trace_length)
            .unwrap_or_else(|err| {
                panic!("invalid trace length: {}", err);
            });
        if self.is_single() {
            f(self.first_step, self.values[0]);
        } else if self.is_periodic() {
            for i in 0..(trace_length / self.stride) {
                f(self.first_step + self.stride * i, self.values[0]);
            }
        } else {
            for (i, &value) in self.values.iter().enumerate() {
                f(self.first_step + self.stride * i, value);
            }
        }
    }

    /// Returns the number of steps against which this assertion will be applied given an
    /// execution trace of the specified length.
    ///
    /// * For single-value assertions, this will always be one.
    /// * For periodic assertions this will be equal to `trace_length` / `stride`.
    /// * For sequence assertions this will be equal to the number of asserted values.
    ///
    /// # Panics
    /// Panics if the specified trace length is not valid for this assertion.
    pub fn get_num_steps(&self, trace_length: usize) -> usize {
        self.validate_trace_length(trace_length)
            .unwrap_or_else(|err| {
                panic!("invalid trace length: {}", err);
            });
        if self.is_single() {
            1
        } else if self.is_periodic() {
            trace_length / self.stride
        } else {
            self.values.len()
        }
    }
}

// OTHER TRAIT IMPLEMENTATIONS
// =================================================================================================

/// We define ordering of assertions to be first by stride, then by first_step, and finally by
/// column in ascending order.
impl<E: FieldElement> Ord for Assertion<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.stride == other.stride {
            if self.first_step == other.first_step {
                self.column.partial_cmp(&other.column).unwrap()
            } else {
                self.first_step.partial_cmp(&other.first_step).unwrap()
            }
        } else {
            self.stride.partial_cmp(&other.stride).unwrap()
        }
    }
}

impl<E: FieldElement> PartialOrd for Assertion<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: FieldElement> Display for Assertion<E> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "(column={}, ", self.column)?;
        match self.stride {
            0 => write!(f, "step={}, ", self.first_step)?,
            _ => {
                let second_step = self.first_step + self.stride;
                write!(f, "steps=[{}, {}, ...], ", self.first_step, second_step)?;
            }
        }
        match self.values.len() {
            1 => write!(f, "value={})", self.values[0]),
            2 => write!(f, "values=[{}, {}])", self.values[0], self.values[1]),
            _ => write!(f, "values=[{}, {}, ...])", self.values[0], self.values[1]),
        }
    }
}

// HELPER FUNCTIONS
// =================================================================================================

fn validate_stride(stride: usize, first_step: usize, column: usize) {
    assert!(
        stride.is_power_of_two(),
        "invalid assertion for column {}: stride must be a power of two, but was {}",
        column,
        stride
    );
    assert!(
        stride >= MIN_STRIDE_LENGTH,
        "invalid assertion for column {}: stride must be at least {}, but was {}",
        column,
        MIN_STRIDE_LENGTH,
        stride
    );
    assert!(
        first_step < stride,
        "invalid assertion for column {}: first step must be smaller than stride ({} steps), but was {}",
        column,
        stride,
        first_step
    );
}
