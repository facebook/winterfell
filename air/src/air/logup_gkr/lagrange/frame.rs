// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

use math::{polynom, FieldElement, StarkField};

/// The evaluation frame for the Lagrange kernel.
///
/// The Lagrange kernel's evaluation frame is different from [`crate::EvaluationFrame`].
/// Specifically,
/// - it only contains evaluations from the Lagrange kernel column compared to all columns in the
///   case of [`crate::EvaluationFrame`])
/// - The column is evaluated at points `x`, `gx`, `g^2 x`, ..., `g^(2^(v-1)) x`, where `x` is an
///   arbitrary point, and `g` is the trace domain generator
#[derive(Debug, Clone)]
pub struct LagrangeKernelEvaluationFrame<E: FieldElement> {
    frame: Vec<E>,
}

impl<E: FieldElement> LagrangeKernelEvaluationFrame<E> {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a Lagrange kernel evaluation frame from the raw column polynomial evaluations.
    pub fn with_values(frame: Vec<E>) -> Self {
        Self { frame }
    }

    /// Constructs an empty Lagrange kernel evaluation frame from the raw column polynomial
    /// evaluations. The frame can subsequently be filled using [`Self::frame_mut`].
    pub fn new(trace_len: usize) -> Self {
        let frame_length = trace_len.ilog2() as usize + 1;
        Self { frame: vec![E::ZERO; frame_length] }
    }

    /// Constructs the frame from the Lagrange kernel column trace polynomial coefficients for an
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

impl<E: FieldElement> Index<usize> for LagrangeKernelEvaluationFrame<E> {
    type Output = E;

    fn index(&self, index: usize) -> &Self::Output {
        &self.frame[index]
    }
}

impl<E: FieldElement> IndexMut<usize> for LagrangeKernelEvaluationFrame<E> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.frame[index]
    }
}
