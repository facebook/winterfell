// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use displaydoc::Display;
use thiserror::Error;

/// Represents an error thrown by the prover during an execution of the protocol
#[derive(Debug, Display, Error)]
pub enum ProverError {
    /// A transition constraint was not satisfied at a certain step {0}
    UnsatisfiedTransitionConstraintError(usize),
    /// The constraint polynomial's components do not all have the same degree, expected {0} but found {1}
    MismatchedConstraintPolynomialDegree(usize, usize),
}

/// Represents an error thrown by the verifier during an execution of the protocol
#[derive(Debug, Display, Error)]
pub enum VerifierError {
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

/// Represents an error thrown during evaluation
#[derive(Debug, Display, Error, PartialEq)]
pub enum AssertionError {
    /// expected trace width to be at least {0}, but was {1}
    TraceWidthTooShort(usize, usize),
    /// expected trace length to be a power of two, but was {0}
    TraceLengthNotPowerOfTwo(usize),
    /// expected trace length to be at least {0}, but was {1}
    TraceLengthTooShort(usize, usize),
    /// expected trace length to be exactly {0}, but was {1}
    TraceLengthNotExact(usize, usize),
}
