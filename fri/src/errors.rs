// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// VERIFIER ERROR
// ================================================================================================

#[derive(Debug, PartialEq)]
pub enum VerifierError {
    /// FRI queries did not match the commitment at layer {0}
    LayerCommitmentMismatch(usize),
    /// FRI evaluations did not match query values at depth {0}
    LayerValuesNotConsistent(usize),
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
            Self::LayerCommitmentMismatch(layer) => {
                write!(f, "FRI queries did not match the commitment at layer {}", layer)
            }
            Self::LayerValuesNotConsistent(layer) => {
                write!(f, "FRI evaluations did not match query values at depth {}", layer)
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

// PROOF SERIALIZATION ERROR
// ================================================================================================

#[derive(Debug, PartialEq)]
pub enum ProofSerializationError {
    /// FRI queries at layer {} could not be deserialized: {0}
    LayerDeserializationError(usize, String),
    /// FRI remainder domain size must be {0}, but was {1}
    InvalidRemainderDomain(usize, usize),
    /// FRI remainder could not be deserialized: {0}
    RemainderDeserializationError(String),
}

impl fmt::Display for ProofSerializationError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayerDeserializationError(layer, err_msg) => {
                write!(f, "FRI queries at layer {} could not be deserialized: {}", layer, err_msg)
            }
            Self::InvalidRemainderDomain(num_remainder_elements, domain_size) => {
                write!(f, "FRI remainder domain size must be {}, but was {}", num_remainder_elements, domain_size)
            }
            Self::RemainderDeserializationError(err_msg) => {
                write!(f, "FRI remainder could not be deserialized: {}", err_msg)
            }
        }
    }
}
