// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// PROVER ERROR
// ================================================================================================
/// Represents an error thrown by the prover during an execution of the protocol
#[derive(Debug, PartialEq)]
pub enum ProverError {
    /// A transition constraint was not satisfied at step {0}
    UnsatisfiedTransitionConstraintError(usize),
    /// The constraint polynomial's components do not all have the same degree; expected {0}, but was {1}
    MismatchedConstraintPolynomialDegree(usize, usize),
}

impl fmt::Display for ProverError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsatisfiedTransitionConstraintError(step) => {
                write!(f, "a transition constraint was not satisfied at step {}", step)
            }
            Self::MismatchedConstraintPolynomialDegree(expected, actual) => {
                write!(f, "the constraint polynomial's components do not all have the same degree; expected {}, but was {}", expected, actual)
            }
        }
    }
}

// VERIFIER ERROR
// ================================================================================================
/// Represents an error thrown by the verifier during an execution of the protocol
#[derive(Debug, PartialEq)]
pub enum VerifierError {
    /// Proof deserialization failed: {0}
    ProofDeserializationError(String),
    /// Verification of low-degree proof failed: {0}
    FriVerificationFailed(fri::VerifierError),
    /// Trace query did not match the commitment
    TraceQueryDoesNotMatchCommitment,
    /// Trace query deserialization failed
    TraceQueryDeserializationFailed,
    /// Constraint query did not match the commitment
    ConstraintQueryDoesNotMatchCommitment,
    /// Constraint query deserialization failed
    ConstraintQueryDeserializationFailed,
    /// Query seed proof-of-work verification failed
    QuerySeedProofOfWorkVerificationFailed,
    /// Out-of-domain frame deserialization failed
    OodFrameDeserializationFailed,
    /// Computation context deserialization failed
    ComputationContextDeserializationFailed,
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofDeserializationError(msg) => {
                write!(f, "proof deserialization failed: {}", msg)
            }
            Self::FriVerificationFailed(err) => {
                write!(f, "verification of low-degree proof failed: {}", err)
            }
            Self::TraceQueryDoesNotMatchCommitment => {
                write!(f, "trace query did not match the commitment")
            }
            Self::TraceQueryDeserializationFailed => {
                write!(f, "trace query deserialization failed")
            }
            Self::ConstraintQueryDoesNotMatchCommitment => {
                write!(f, "constraint query did not match the commitment")
            }
            Self::ConstraintQueryDeserializationFailed => {
                write!(f, "constraint query deserialization failed")
            }
            Self::QuerySeedProofOfWorkVerificationFailed => {
                write!(f, "query seed proof-of-work verification failed")
            }
            Self::OodFrameDeserializationFailed => {
                write!(f, "out-of-domain frame deserialization failed")
            }
            Self::ComputationContextDeserializationFailed => {
                write!(f, "computation context deserialization failed")
            }
        }
    }
}

// ASSERTION ERROR
// ================================================================================================
/// Represents an error thrown during evaluation
#[derive(Debug, PartialEq)]
pub enum AssertionError {
    /// Expected trace width to be at least {0}, but was {1}
    TraceWidthTooShort(usize, usize),
    /// Expected trace length to be a power of two, but was {0}
    TraceLengthNotPowerOfTwo(usize),
    /// Expected trace length to be at least {0}, but was {1}
    TraceLengthTooShort(usize, usize),
    /// Expected trace length to be exactly {0}, but was {1}
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

// PROOF SERIALIZATION ERROR
// ================================================================================================

#[derive(Debug, PartialEq)]
pub enum ProofSerializationError {
    /// Failed to parse commitments: {0}
    FailedToParseCommitments(String),
    /// Too many commitment bytes; expected {0}, but was {1}
    TooManyCommitmentBytes(usize, usize),
    /// Failed to parse query values: {0}
    FailedToParseQueryValues(String),
    /// Failed to parse query authentication paths: {0}
    FailedToParseQueryProofs(String),
}

impl fmt::Display for ProofSerializationError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToParseCommitments(msg) => {
                write!(f, "failed to parse commitments: {}", msg)
            }
            Self::TooManyCommitmentBytes(expected, actual) => {
                write!(f, "too many commitment bytes; expected {}, but was {}", expected, actual)
            }
            Self::FailedToParseQueryValues(msg) => {
                write!(f, "failed to parse query values: {}", msg)
            }
            Self::FailedToParseQueryProofs(msg) => {
                write!(f, " failed to parse query authentication paths: {}", msg)
            }
        }
    }
}
