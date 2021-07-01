// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// DIGEST SERIALIZATION ERROR
// ================================================================================================
#[derive(Debug, PartialEq)]
pub enum DigestSerializationError {
    /// Not enough bytes for {0} digests; expected {1} bytes, but was {2}
    TooFewBytesForDigests(usize, usize, usize),
}

impl fmt::Display for DigestSerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewBytesForDigests(num_digests, expected, actual) => {
                write!(
                    f,
                    "Not enough bytes for {} digests; expected {} bytes, but was {}",
                    num_digests, expected, actual
                )
            }
        }
    }
}

// PROOF SERIALIZATION ERROR
// ================================================================================================
#[derive(Debug, PartialEq)]
pub enum ProofSerializationError {
    /// No node bytes provided
    NoNodeBytes,
    /// Unexpected EOF at position {0}
    UnexpectedEof(usize),
}

impl fmt::Display for ProofSerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNodeBytes => {
                write!(f, "no node bytes provided")
            }
            Self::UnexpectedEof(pos) => {
                write!(f, "Unexpected EOF at position {}", pos)
            }
        }
    }
}

// PUBLIC COIN ERROR
// ================================================================================================

/// Defines errors which can occur when drawing values from a public coin.
#[derive(Debug, PartialEq)]
pub enum PublicCoinError {
    /// A valid element could not be drawn from the field after the specified number of tries.
    FailedToDrawFieldElement(usize),
    /// The required number of integer values could not be drawn from the specified domain after
    /// the specified number of tries.
    FailedToDrawIntegers(usize, usize, usize),
}

impl fmt::Display for PublicCoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToDrawFieldElement(num_tries) => {
                write!(
                    f,
                    "failed to generate a valid field element after {} tries",
                    num_tries
                )
            }
            Self::FailedToDrawIntegers(num_expected, num_actual, num_tries) => {
                write!(
                    f,
                    "needed to draw {} integers from a domain, but drew only {} after {} tries",
                    num_expected, num_actual, num_tries
                )
            }
        }
    }
}
