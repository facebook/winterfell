// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;

// PROVER ERROR
// ================================================================================================
/// Represents an error thrown by the prover during an execution of the protocol.
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
/// Represents an error thrown by the verifier during an execution of the protocol.
#[derive(Debug, PartialEq)]
pub enum VerifierError {
    /// Base field of the proof does not match base field of the specified AIR
    InconsistentBaseField,
    /// Proof deserialization failed: {0}
    ProofDeserializationError(String),
    /// Failed to draw a random value from a random coin.
    RandomCoinError,
    /// Constraint evaluations over the out-of-domain frame are inconsistent
    InconsistentOodConstraintEvaluations,
    /// Trace query does not match the commitment
    TraceQueryDoesNotMatchCommitment,
    /// Constraint query does not match the commitment
    ConstraintQueryDoesNotMatchCommitment,
    /// Query seed proof-of-work verification failed
    QuerySeedProofOfWorkVerificationFailed,
    /// Verification of low-degree proof failed: {0}
    FriVerificationFailed(fri::VerifierError),
}

impl fmt::Display for VerifierError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InconsistentBaseField =>  {
                write!(f, "base field of the proof does not match base field of the specified AIR")
            }
            Self::ProofDeserializationError(msg) => {
                write!(f, "proof deserialization failed: {}", msg)
            }
            Self::RandomCoinError => {
                write!(f, "failed to draw a random value from a random coin")
            }
            Self::InconsistentOodConstraintEvaluations => {
                write!(f, "constraint evaluations over the out-of-domain frame are inconsistent")
            }
            Self::TraceQueryDoesNotMatchCommitment => {
                write!(f, "trace query did not match the commitment")
            }
            Self::ConstraintQueryDoesNotMatchCommitment => {
                write!(f, "constraint query did not match the commitment")
            }
            Self::QuerySeedProofOfWorkVerificationFailed => {
                write!(f, "query seed proof-of-work verification failed")
            }
            Self::FriVerificationFailed(err) => {
                write!(f, "verification of low-degree proof failed: {}", err)
            }
        }
    }
}

// ASSERTION ERROR
// ================================================================================================
/// Represents an error thrown during assertion evaluation.
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
