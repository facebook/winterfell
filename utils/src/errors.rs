// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// DESERIALIZATION ERROR
// ================================================================================================

#[derive(Debug, PartialEq)]
pub enum DeserializationError {
    /// Unexpected EOF
    UnexpectedEOF,
    /// Unknown error: {0}
    UnknownError(String),
}

impl fmt::Display for DeserializationError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEOF => {
                write!(f, "unexpected EOF")
            }
            Self::UnknownError(err_msg) => {
                write!(f, "unknown error: {}", err_msg)
            }
        }
    }
}
