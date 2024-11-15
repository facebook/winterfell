// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::string::String;
use core::fmt;

// DESERIALIZATION ERROR
// ================================================================================================

/// Defines errors which can occur during deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeserializationError {
    /// Bytes in the input do not represent a valid value.
    InvalidValue(String),
    /// An end of input was reached before a valid value could be deserialized.
    UnexpectedEOF,
    /// Deserialization has finished but not all bytes have been consumed.
    UnconsumedBytes,
    /// An unknown error has occurred.
    UnknownError(String),
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(err_msg) => write!(f, "{err_msg}"),
            Self::UnexpectedEOF => write!(f, "unexpected EOF"),
            Self::UnconsumedBytes => write!(f, "not all bytes were consumed"),
            Self::UnknownError(err_msg) => write!(f, "unknown error: {err_msg}"),
        }
    }
}

impl core::error::Error for DeserializationError {}
