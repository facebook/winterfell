// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;
use utils::string::String;

use crypto::RandomCoinError;

// VERIFIER ERROR
// ================================================================================================

/// Defines errors which can occur during FRI proof verification.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifierError {
    /// Attempt to draw a random value from a public coin failed.
    PublicCoinError(RandomCoinError),
    /// Folding factor specified for the protocol is not supported. Currently, supported folding
    /// factors are: 4, 8, and 16.
    UnsupportedFoldingFactor(usize),
    /// Number of query positions does not match the number of provided evaluations.
    NumPositionEvaluationMismatch(usize, usize),
    /// Evaluations at queried positions did not match layer commitment made by the prover.
    LayerCommitmentMismatch,
    /// Degree-respecting projection was not performed correctly at one of the layers.
    InvalidLayerFolding(usize),
    /// Failed to construct a Merkle tree out of FRI remainder values.
    RemainderTreeConstructionFailed(String),
    /// FRI remainder did not match the commitment.
    RemainderCommitmentMismatch,
    /// Degree-respecting projection was not performed correctly at the last layer.
    InvalidRemainderFolding,
    /// FRI remainder expected degree is greater than number of remainder values.
    RemainderDegreeNotValid,
    /// FRI remainder degree is greater than the polynomial degree expected for the last layer.
    RemainderDegreeMismatch(usize),
    /// Polynomial degree at one of the FRI layers could not be divided evenly by the folding factor.
    DegreeTruncation(usize, usize, usize),
}

impl fmt::Display for VerifierError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicCoinError(err) => {
                write!(f, "failed to draw a random value from the public coin: {}", err)
            }
            Self::UnsupportedFoldingFactor(value) => {
                write!(f, "folding factor {} is not currently supported", value)
            }
            Self::NumPositionEvaluationMismatch(num_positions, num_evaluations) => write!(f,
                "the number of query positions must be the same as the number of polynomial evaluations, but {} and {} were provided",
                num_positions, num_evaluations
            ),
            Self::LayerCommitmentMismatch => {
                write!(f, "FRI queries did not match layer commitment made by the prover")
            }
            Self::InvalidLayerFolding(layer) => {
                write!(f, "degree-respecting projection is not consistent at layer {}", layer)
            }
            Self::RemainderTreeConstructionFailed(err_msg) => {
                write!(f, "FRI remainder Merkle tree could not be constructed: {}", err_msg)
            }
            Self::RemainderCommitmentMismatch => {
                write!(f, "FRI remainder did not match the commitment")
            }
            Self::InvalidRemainderFolding => {
                write!(f, "degree-respecting projection is inconsistent at the last FRI layer")
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
