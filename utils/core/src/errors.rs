// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::string::String;
use core::fmt;

// DESERIALIZATION ERROR
// ================================================================================================

/// Defines errors which can occur during deserialization.
#[derive(Debug, PartialEq, Eq)]
pub enum DeserializationError {
    /// Bytes in the input do not represent a valid value.
    InvalidValue(String),
    /// An invalid proof option was chosen
    ProofOption(ProofOptionError),
    /// An end of input was reached before a valid value could be deserialized.
    UnexpectedEOF,
    /// Deserialization has finished but not all bytes have been consumed.
    UnconsumedBytes,
    /// An unknown error has occurred.
    UnknownError(String),
}

impl fmt::Display for DeserializationError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(err_msg) => {
                write!(f, "{err_msg}")
            }
            Self::ProofOption(error) => error.fmt(f),
            Self::UnexpectedEOF => {
                write!(f, "unexpected EOF")
            }
            Self::UnconsumedBytes => {
                write!(f, "not all bytes were consumed")
            }
            Self::UnknownError(err_msg) => {
                write!(f, "unknown error: {err_msg}")
            }
        }
    }
}

impl From<ProofOptionError> for DeserializationError {
    fn from(error: ProofOptionError) -> Self {
        Self::ProofOption(error)
    }
}

// PROOF OPTION ERROR
// ================================================================================================

// Surfaces errors with particular ProofOption values that are requested
#[derive(Debug, Eq, PartialEq)]
pub enum ProofOptionError {
    NumberOfQueries,
    GrindingFactor,
}

impl fmt::Display for ProofOptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::NumberOfQueries => "number of queries cannot be greater than 128",
                Self::GrindingFactor => "grinding factor cannot be greater than 32",
            }
        )
    }
}
