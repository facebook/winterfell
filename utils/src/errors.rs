// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// DESERIALIZATION ERROR
// ================================================================================================

/// Defines errors which can occur during deserialization.
#[derive(Debug, PartialEq)]
pub enum DeserializationError {
    /// A value read from the input could not be deserialized into a valid value.
    InvalidValue(String, String),
    /// An end of input was reached before a valid value could be deserialized.
    UnexpectedEOF,
    /// An unknown error has occurred.
    UnknownError(String),
}

impl fmt::Display for DeserializationError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(value, type_name) => {
                write!(f, "value {} cannot be deserialized as {}", value, type_name)
            }
            Self::UnexpectedEOF => {
                write!(f, "unexpected EOF")
            }
            Self::UnknownError(err_msg) => {
                write!(f, "unknown error: {}", err_msg)
            }
        }
    }
}
