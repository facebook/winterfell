// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// DESERIALIZATION ERROR
// ================================================================================================

#[derive(Debug, PartialEq)]
pub enum DeserializationError {
    /// Value {0} cannot be deserialized as {}
    InvalidValue(String, String),
    /// Unexpected EOF
    UnexpectedEOF,
    /// Unknown error: {0}
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
