// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains common error types for prover and verifier.

use core::fmt;

// PROVER ERROR
// ================================================================================================
/// Represents an error returned by the prover during an execution of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProverError {
    /// This error occurs when a transition constraint evaluated over a specific execution trace
    /// does not evaluate to zero at any of the steps.
    UnsatisfiedTransitionConstraintError(usize),
    /// This error occurs when polynomials built from the columns of a constraint evaluation
    /// table do not all have the same degree.
    MismatchedConstraintPolynomialDegree(usize, usize),
    /// This error occurs when the base field specified by the AIR does not support field extension
    /// of degree specified by proof options.
    UnsupportedFieldExtension(usize),
}

impl fmt::Display for ProverError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsatisfiedTransitionConstraintError(step) => {
                write!(f, "a transition constraint was not satisfied at step {step}")
            }
            Self::MismatchedConstraintPolynomialDegree(expected, actual) => {
                write!(f, "the constraint polynomial's components do not all have the same degree; expected {expected}, but was {actual}")
            }
            Self::UnsupportedFieldExtension(degree) => {
                write!(f, "field extension of degree {degree} is not supported for the specified base field")
            }
        }
    }
}

impl core::error::Error for ProverError {}
