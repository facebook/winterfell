// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

#[derive(Debug, PartialEq)]
pub enum VerifierError {
    /// FRI queries did not match the commitment at layer {0}
    LayerCommitmentMismatch(usize),
    /// FRI queries at layer {} could not be deserialized: {0}
    LayerDeserializationError(usize, String),
    /// FRI evaluations did not match query values at depth {0}
    LayerValuesNotConsistent(usize),
    /// FRI remainder did not match the commitment
    RemainderCommitmentMismatch,
    /// FRI remainder could not be deserialized: {0}
    RemainderDeserializationError(String),
    /// FRI remainder values are inconsistent with values of the last column
    RemainderValuesNotConsistent,
    /// FRI remainder expected degree is greater than number of remainder values
    RemainderDegreeNotValid,
    /// "FRI remainder is not a valid degree {0} polynomial
    RemainderDegreeMismatch(usize),
}

impl fmt::Display for VerifierError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayerCommitmentMismatch(layer) => {
                write!(f, "FRI queries did not match the commitment at layer {}", layer)
            }
            Self::LayerDeserializationError(layer, err_msg) => {
                write!(f, "FRI queries at layer {} could not be deserialized: {}", layer, err_msg)
            }
            Self::LayerValuesNotConsistent(layer) => {
                write!(f, "FRI evaluations did not match query values at depth {}", layer)
            }
            Self::RemainderCommitmentMismatch => {
                write!(f, "FRI remainder did not match the commitment")
            }
            Self::RemainderDeserializationError(err_msg) => {
                write!(f, "FRI remainder could not be deserialized: {}", err_msg)
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
        }
    }
}
