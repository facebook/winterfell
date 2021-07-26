// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains common error types for prover and verifier.

use core::fmt;

// PROVER ERROR
// ================================================================================================
/// Represents an error returned by the prover during an execution of the protocol.
#[derive(Debug, PartialEq)]
pub enum ProverError {
    /// This error occurs when a transition constraint evaluated over a specific execution trace
    /// does not evaluate to zero at any of the steps.
    UnsatisfiedTransitionConstraintError(usize),
    /// This error occurs when polynomials built from the columns of a constraint evaluation
    /// table do not all have the same degree.
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
/// Represents an error returned by the verifier during an execution of the protocol.
#[derive(Debug, PartialEq)]
pub enum VerifierError {
    /// This error occurs when base field read by a verifier from a proof does not match the
    /// base field of AIR with which the verifier was instantiated.
    InconsistentBaseField,
    /// This error occurs when a verifier cannot deserialize the specified proof.
    ProofDeserializationError(String),
    /// This error occurs when a verifier fails to draw a random value from a random coin
    /// within a specified number of tries.
    RandomCoinError,
    /// This error occurs when constraints evaluated over out-of-domain trace rows do not match
    /// evaluations of the constraint composition polynomial at the out-of-domain point.
    InconsistentOodConstraintEvaluations,
    /// This error occurs when Merkle authentication paths of trace queries do not resolve to the
    /// execution trace commitment included in the proof.
    TraceQueryDoesNotMatchCommitment,
    /// This error occurs when Merkle authentication paths of constraint evaluation queries do not
    /// resolve to the constraint evaluation commitment included in the proof.
    ConstraintQueryDoesNotMatchCommitment,
    /// This error occurs when the proof-of-work nonce hashed with the current state of the public
    /// coin resolves to a value which does not meet the proof-of-work threshold specified by the
    // proof options.
    QuerySeedProofOfWorkVerificationFailed,
    /// This error occurs when the DEEP composition polynomial evaluations derived from trace and
    /// constraint evaluation queries do not represent a polynomial of the degree expected by the
    /// verifier.
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
/// Represents an error returned during assertion evaluation.
#[derive(Debug, PartialEq)]
pub enum AssertionError {
    /// This error occurs when an assertion is evaluated against an execution trace which does not
    /// contain a register specified by the assertion.
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
