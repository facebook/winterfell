// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// SERIALIZATION ERROR
// ================================================================================================
#[derive(Debug, PartialEq)]
pub enum SerializationError {
    /// Destination must be at least {0} elements long, but was {1}
    DestinationTooSmall(usize, usize),
    /// Expected source to contain exactly {0} bytes, but was {1}
    WrongNumberOfBytes(usize, usize),
    /// Failed to read field element from bytes at position {0}
    FailedToReadElement(usize),
    /// Number of bytes ({0}) does not divide into whole number of field elements
    NotEnoughBytesForWholeElements(usize),
    /// Slice memory alignment is not valid for this field element type
    InvalidMemoryAlignment,
}

impl fmt::Display for SerializationError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationTooSmall(expected, actual) => {
                write!(f, "destination must be at least {} elements long, but was {}", expected, actual)
            }
            Self::WrongNumberOfBytes(expected, actual) => {
                write!(f, "expected source to contain exactly {} bytes, but was {}", expected, actual)
            }
            Self::FailedToReadElement(position) => {
                write!(f, "failed to read field element from bytes at position {}", position)
            }
            Self::NotEnoughBytesForWholeElements(num_bytes) => {
                write!(f, "number of bytes ({}) does not divide into whole number of field elements", num_bytes)
            }
            Self::InvalidMemoryAlignment => {
                write!(f, "slice memory alignment is not valid for this field element type")
            }
        }
    }
}

// ELEMENT DECODING ERROR
// ================================================================================================
#[derive(Debug, PartialEq)]
pub enum ElementDecodingError {
    /// Not enough bytes for a full field element; expected {0} bytes, but was {1} bytes
    NotEnoughBytes(usize, usize),
    /// Too many bytes for a field element; expected {0} bytes, but was {1} bytes
    TooManyBytes(usize, usize),
    /// Invalid field element: value {0} is greater than or equal to the field modulus
    ValueTooLarger(String),
    /// Unknown error: {0}
    UnknownError(String),
}

impl fmt::Display for ElementDecodingError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughBytes(expected, actual) => {
                write!(f, "not enough bytes for a full field element; expected {} bytes, but was {} bytes", expected, actual)
            }
            Self::TooManyBytes(expected, actual) => {
                write!(f, "too many bytes for a field element; expected {} bytes, but was {} bytes", expected, actual)
            }
            Self::ValueTooLarger(value) => {
                write!(f, "invalid field element: value {} is greater than or equal to the field modulus", value)
            }
            Self::UnknownError(err_msg) => {
                write!(f, "unknown error: {}", err_msg)
            }
        }
    }
}
