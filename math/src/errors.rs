// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SerializationError {
    #[error("destination must be at least {0} elements long, but was {1}")]
    DestinationTooSmall(usize, usize),

    #[error("failed to read field element from bytes at position {0}")]
    FailedToReadElement(usize),

    #[error("number of bytes ({0}) does not divide into whole number of field elements")]
    NotEnoughBytesForWholeElements(usize),

    #[error("slice memory alignment is not valid for this field element type")]
    InvalidMemoryAlignment,
}

#[derive(Error, Debug, PartialEq)]
pub enum ElementDecodingError {
    #[error("not enough bytes for a full field element; expected {0} bytes, but was {1} bytes")]
    NotEnoughBytes(usize, usize),

    #[error("too many bytes for a field element; expected {0} bytes, but was {1} bytes")]
    TooManyBytes(usize, usize),

    #[error("invalid field element: value {0} is greater than or equal to the field modulus")]
    ValueTooLarger(String),

    #[error("{0}")]
    UnknownError(String),
}
