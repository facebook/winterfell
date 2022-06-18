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
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceWidthTooShort(expected, actual) => {
                write!(f, "expected trace width to be at least {}, but was {}", expected, actual)
            }
            Self::TraceLengthNotPowerOfTwo(actual) => {
                write!(f, "expected trace length to be a power of two, but was {}", actual)
            }
            Self::TraceLengthTooShort(expected, actual) => {
                write!(f, "expected trace length to be at least {}, but was {}", expected, actual)
            }
            Self::TraceLengthNotExact(expected, actual) => {
                write!(f, "expected trace length to be exactly {}, but was {}", expected, actual)
            }
        }
    }
}
