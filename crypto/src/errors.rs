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
    UnexpectedEOF(usize),
}

impl fmt::Display for ProofSerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNodeBytes => {
                write!(f, "no node bytes provided")
            }
            Self::UnexpectedEOF(pos) => {
                write!(f, "Unexpected EOF at position {}", pos)
            }
        }
    }
}
