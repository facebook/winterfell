// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::FieldElement;
use math::{polynom, StarkField};
use utils::collections::*;

// EVALUATION FRAME
// ================================================================================================

/// A set of execution trace rows required for evaluation of transition constraints.
///
/// In the current implementation, an evaluation frame always contains two consecutive rows of the
/// execution trace. It is passed in as one of the parameters into
/// [Air::evaluate_transition()](crate::Air::evaluate_transition) function.
#[derive(Debug, Clone)]
pub struct EvaluationFrame<E: FieldElement> {
    current: Vec<E>,
    next: Vec<E>,
}

impl<E: FieldElement> EvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new evaluation frame instantiated with the specified number of columns.
    ///
    /// # Panics
    /// Panics if `num_columns` is zero.
    pub fn new(num_columns: usize) -> Self {
        assert!(num_columns > 0, "number of columns must be greater than zero");
        EvaluationFrame {
            current: E::zeroed_vector(num_columns),
            next: E::zeroed_vector(num_columns),
        }
    }

    /// Returns a new evaluation frame instantiated from the provided rows.
    ///
    /// # Panics
    /// Panics if:
    /// * Lengths of the provided rows are zero.
    /// * Lengths of the provided rows are not the same.
    pub fn from_rows(current: Vec<E>, next: Vec<E>) -> Self {
        assert!(!current.is_empty(), "a row must contain at least one value");
        assert_eq!(current.len(), next.len(), "number of values in the rows must be the same");
        Self { current, next }
    }

    // ROW ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the current row.
    #[inline(always)]
    pub fn current(&self) -> &[E] {
        &self.current
    }

    /// Returns a reference to the next row.
    #[inline(always)]
    pub fn next(&self) -> &[E] {
        &self.next
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the current row.
    #[inline(always)]
    pub fn current_mut(&mut self) -> &mut [E] {
        &mut self.current
    }

    /// Returns a mutable reference to the next row.
    #[inline(always)]
    pub fn next_mut(&mut self) -> &mut [E] {
        &mut self.next
    }
}

// LAGRANGE KERNEL EVALUATION FRAME
// ================================================================================================

/// The evaluation frame for the Lagrange kernel.
///
/// The Lagrange kernel's evaluation frame is different from [`EvaluationFrame`]. Specifically,
/// - it only contains evaluations from the Lagrange kernel column
///   (compared to all columns in the case of [`EvaluationFrame`])
/// - The column is evaluated at points `x`, `gx`, `g^2 x`, ..., `g^(2^(v-1)) x`,
///   where `x` is an arbitrary point, and `g` is the trace domain generator
#[derive(Debug, Clone)]
pub struct LagrangeKernelEvaluationFrame<E: FieldElement> {
    frame: Vec<E>,
}

impl<E: FieldElement> LagrangeKernelEvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a Lagrange kernel evaluation frame from the raw column polynomial evaluations.
    pub fn new(frame: Vec<E>) -> Self {
        Self { frame }
    }

    /// Constructs an empty Lagrange kernel evaluation frame from the raw column polynomial evaluations. The frame can subsequently be filled using [`Self::frame_mut`].
    pub fn new_empty() -> Self {
        Self { frame: Vec::new() }
    }

    /// Constructs the frame from the Lagrange kernel trace column polynomial coefficients for an
    /// evaluation point.
    pub fn from_lagrange_kernel_column_poly(lagrange_kernel_col_poly: &[E], z: E) -> Self {
        let log_trace_len = lagrange_kernel_col_poly.len().ilog2();
        let g = E::from(E::BaseField::get_root_of_unity(log_trace_len));

        let mut frame = Vec::with_capacity(log_trace_len as usize + 1);

        // push c(x)
        frame.push(polynom::eval(lagrange_kernel_col_poly, z));

        // push c(z * g), c(z * g^2), c(z * g^4), ..., c(z * g^(2^(v-1)))
        let mut g_exp = g;
        for _ in 0..log_trace_len {
            let x = g_exp * z;
            let lagrange_poly_at_x = polynom::eval(lagrange_kernel_col_poly, x);

            frame.push(lagrange_poly_at_x);

            // takes on the values `g`, `g^2`, `g^4`, `g^8`, ...
            g_exp *= g_exp;
        }

        Self { frame }
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------
    pub fn frame_mut(&mut self) -> &mut Vec<E> {
        &mut self.frame
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the inner frame.
    pub fn inner(&self) -> &[E] {
        &self.frame
    }

    /// Returns the number of rows in the frame.
    ///
    /// This is equal to `log(trace_length) + 1`.
    pub fn num_rows(&self) -> usize {
        self.frame.len()
    }
}
