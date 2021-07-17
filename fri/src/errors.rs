// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// VERIFIER ERROR
// ================================================================================================

/// Defines errors which can occur during FRI proof verification.
#[derive(Debug, PartialEq)]
pub enum VerifierError {
    ///
    PublicCoinError,
    /// Folding factor specified by the verifier context is not supported. Currently supported
    /// folding factors are: 4, 8, and 16.
    UnsupportedFoldingFactor(usize),
    /// Number of query positions did not match the number of query evaluations.
    NumPositionEvaluationMismatch(usize, usize),
    /// Evaluations at queried positions did not match layer commitment made by the prover.
    LayerCommitmentMismatch,
    /// FRI evaluations did not match query values at depth {0}
    LayerValuesNotConsistent(usize),
    /// Failed to construct a Merkle tree out of FRI remainder values.
    RemainderTreeConstructionFailed(String),
    /// FRI remainder did not match the commitment
    RemainderCommitmentMismatch,
    /// FRI remainder values are inconsistent with values of the last column
    RemainderValuesNotConsistent,
    /// FRI remainder expected degree is greater than number of remainder values
    RemainderDegreeNotValid,
    /// "FRI remainder is not a valid degree {0} polynomial
    RemainderDegreeMismatch(usize),
    /// Degree reduction from {0} by {1} at layer {2} results in degree truncation
    DegreeTruncation(usize, usize, usize),
}

impl fmt::Display for VerifierError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicCoinError => {
                write!(f, "failed to draw a random value from a public coin")
            }
            Self::UnsupportedFoldingFactor(value) => {
                write!(f, "folding factor {} is not currently supported", value)
            }
            Self::NumPositionEvaluationMismatch(num_positions, num_evaluations) => write!(f,
                "the number of query positions must be the same as the number of query evaluations, but {} and {} were provided",
                num_positions, num_evaluations
            ),
            Self::LayerCommitmentMismatch => {
                write!(f, "FRI queries did not match layer commitment made by the prover")
            }
            Self::LayerValuesNotConsistent(layer) => {
                write!(f, "FRI evaluations did not match query values at layer {}", layer)
            }
            Self::RemainderTreeConstructionFailed(err_msg) => {
                write!(f, "FRI remainder Merkle tree could not be constructed: {}", err_msg)
            }
            Self::RemainderCommitmentMismatch => {
                write!(f, "FRI remainder did not match the commitment")
            }
            Self::RemainderValuesNotConsistent => {
                write!(f, "FRI remainder values are inconsistent with values of the last column")
            }
            Self::RemainderDegreeNotValid => {
                write!(f, "FRI remainder expected degree is greater than number of remainder values")
            }
            Self::RemainderDegreeMismatch(degree) => {
                write!(f, "FRI remainder is not a valid degree {} polynomial", degree)
            }
            Self::DegreeTruncation(degree, folding, layer) => {
                write!(f, "degree reduction from {} by {} at layer {} results in degree truncation", degree, folding, layer)
            }
        }
    }
}
