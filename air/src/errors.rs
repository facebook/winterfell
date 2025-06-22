// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// ASSERTION ERROR
// ================================================================================================
/// Represents an error returned during assertion evaluation.
#[derive(Debug, PartialEq, Eq)]
pub enum AssertionError {
    /// This error occurs when an assertion is evaluated against an execution trace which does not
    /// contain a column specified by the assertion.
    TraceWidthTooShort(usize, usize),
    /// This error occurs when an assertion is evaluated against an execution trace with length
    /// which is not a power of two.
    TraceLengthNotPowerOfTwo(usize),
    /// This error occurs when an assertion is evaluated against an execution trace which does not
    /// contain a step against which the assertion is placed.
    TraceLengthTooShort(usize, usize),
    /// This error occurs when a `Sequence` assertion is placed against an execution trace with
    /// length which conflicts with the trace length implied by the assertion.
    TraceLengthNotExact(usize, usize),
}

impl fmt::Display for AssertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceWidthTooShort(expected, actual) => {
                write!(f, "expected trace width to be at least {expected}, but was {actual}")
            },
            Self::TraceLengthNotPowerOfTwo(actual) => {
                write!(f, "expected trace length to be a power of two, but was {actual}")
            },
            Self::TraceLengthTooShort(expected, actual) => {
                write!(f, "expected trace length to be at least {expected}, but was {actual}")
            },
            Self::TraceLengthNotExact(expected, actual) => {
                write!(f, "expected trace length to be exactly {expected}, but was {actual}")
            },
        }
    }
}

impl core::error::Error for AssertionError {}

// PROOF OPTIONS ERROR
// ================================================================================================
/// Represents an error returned during proof options validation.
#[derive(Debug, PartialEq, Eq)]
pub enum ProofOptionsError {
    /// This error occurs when the number of queries is zero.
    NumQueriesTooSmall,
    /// This error occurs when the number of queries is greater than the maximum allowed.
    NumQueriesTooLarge(usize, usize),
    /// This error occurs when the blowup factor is not a power of two.
    BlowupFactorNotPowerOfTwo(usize),
    /// This error occurs when the blowup factor is smaller than the minimum allowed.
    BlowupFactorTooSmall(usize, usize),
    /// This error occurs when the blowup factor is greater than the maximum allowed.
    BlowupFactorTooLarge(usize, usize),
    /// This error occurs when the grinding factor is greater than the maximum allowed.
    GrindingFactorTooLarge(u32, u32),
    /// This error occurs when the FRI folding factor is not a power of two.
    FriFoldingFactorNotPowerOfTwo(usize),
    /// This error occurs when the FRI folding factor is smaller than the minimum allowed.
    FriFoldingFactorTooSmall(usize, usize),
    /// This error occurs when the FRI folding factor is greater than the maximum allowed.
    FriFoldingFactorTooLarge(usize, usize),
    /// This error occurs when the FRI remainder max degree is not one less than a power of two.
    FriRemainderDegreeInvalid(usize),
    /// This error occurs when the FRI remainder max degree is greater than the maximum allowed.
    FriRemainderDegreeTooLarge(usize, usize),
    /// This error occurs when the number of partitions is zero.
    PartitionCountTooSmall,
    /// This error occurs when the number of partitions is greater than the maximum allowed.
    PartitionCountTooLarge(usize, usize),
    /// This error occurs when the hash rate is zero.
    HashRateTooSmall,
    /// This error occurs when the hash rate is greater than the maximum allowed.
    HashRateTooLarge(usize, usize),
}

impl fmt::Display for ProofOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumQueriesTooSmall => {
                write!(f, "number of queries must be greater than 0")
            },
            Self::NumQueriesTooLarge(value, max) => {
                write!(f, "number of queries cannot be greater than {max}, but was {value}")
            },
            Self::BlowupFactorNotPowerOfTwo(value) => {
                write!(f, "blowup factor must be a power of 2, but was {value}")
            },
            Self::BlowupFactorTooSmall(value, min) => {
                write!(f, "blowup factor cannot be smaller than {min}, but was {value}")
            },
            Self::BlowupFactorTooLarge(value, max) => {
                write!(f, "blowup factor cannot be greater than {max}, but was {value}")
            },
            Self::GrindingFactorTooLarge(value, max) => {
                write!(f, "grinding factor cannot be greater than {max}, but was {value}")
            },
            Self::FriFoldingFactorNotPowerOfTwo(value) => {
                write!(f, "FRI folding factor must be a power of 2, but was {value}")
            },
            Self::FriFoldingFactorTooSmall(value, min) => {
                write!(f, "FRI folding factor cannot be smaller than {min}, but was {value}")
            },
            Self::FriFoldingFactorTooLarge(value, max) => {
                write!(f, "FRI folding factor cannot be greater than {max}, but was {value}")
            },
            Self::FriRemainderDegreeInvalid(value) => {
                write!(f, "FRI polynomial remainder degree must be one less than a power of two, but was {value}")
            },
            Self::FriRemainderDegreeTooLarge(value, max) => {
                write!(f, "FRI polynomial remainder degree cannot be greater than {max}, but was {value}")
            },
            Self::PartitionCountTooSmall => {
                write!(f, "number of partitions must be greater than 0")
            },
            Self::PartitionCountTooLarge(value, max) => {
                write!(f, "number of partitions cannot be greater than {max}, but was {value}")
            },
            Self::HashRateTooSmall => {
                write!(f, "hash rate must be greater than 0")
            },
            Self::HashRateTooLarge(value, max) => {
                write!(f, "hash rate cannot be greater than {max}, but was {value}")
            },
        }
    }
}

impl core::error::Error for ProofOptionsError {}
