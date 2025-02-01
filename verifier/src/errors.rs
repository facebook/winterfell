// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains common error types for prover and verifier.

use alloc::string::String;
use core::fmt;

// VERIFIER ERROR
// ================================================================================================
/// Represents an error returned by the verifier during an execution of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// This error occurs when base field read by a verifier from a proof does not match the
    /// base field of AIR with which the verifier was instantiated.
    InconsistentBaseField,
    /// This error occurs when the base field in which the proof was generated does not support
    /// field extension of degree specified by the proof.
    UnsupportedFieldExtension(usize),
    /// This error occurs when a verifier cannot deserialize the specified proof.
    ProofDeserializationError(String),
    /// This error occurs when a verifier fails to draw a random value from a random coin
    /// within a specified number of tries.
    RandomCoinError,
    /// This error occurs when constraints evaluated over out-of-domain trace rows do not match
    /// evaluations of the constraint composition polynomial at the out-of-domain point.
    InconsistentOodConstraintEvaluations,
    /// This error occurs when the batch opening proof fails to verify for trace queries.
    TraceQueryDoesNotMatchCommitment,
    /// This error occurs when the batch opening proof fails to verify for constraint evaluation
    /// queries.
    ConstraintQueryDoesNotMatchCommitment,
    /// This error occurs when the proof-of-work nonce hashed with the current state of the public
    /// coin resolves to a value which does not meet the proof-of-work threshold specified by the
    // proof options.
    QuerySeedProofOfWorkVerificationFailed,
    /// This error occurs when the DEEP composition polynomial evaluations derived from trace and
    /// constraint evaluation queries do not represent a polynomial of the degree expected by the
    /// verifier.
    FriVerificationFailed(fri::VerifierError),
    /// This error occurs when the parameters, that were used to generate the proof, do not provide
    /// a conjectured security level greater than or equal to the conjectured security level
    /// expected by the verifier.
    InsufficientConjecturedSecurity(u32, u32),
    /// This error occurs when the parameters, that were used to generate the proof, do not provide
    /// a proven security level greater than or equal to the proven security level expected by
    /// the verifier.
    InsufficientProvenSecurity(u32, u32),
    /// This error occurs when the parameters, that were used to generate the proof, do not match
    /// any of the set of parameters expected by the verifier.
    UnacceptableProofOptions,
}

impl fmt::Display for VerifierError {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InconsistentBaseField =>  {
                write!(f, "base field of the proof does not match base field of the specified AIR")
            }
            Self::UnsupportedFieldExtension(degree) => {
                write!(f, "field extension of degree {degree} is not supported for the proof base field")
            }
            Self::ProofDeserializationError(msg) => {
                write!(f, "proof deserialization failed: {msg}")
            }
            Self::RandomCoinError => {
                write!(f, "failed to draw a random value from a random coin")
            }
            Self::InconsistentOodConstraintEvaluations => {
                write!(f, "constraint evaluations over the out-of-domain frame are inconsistent")
            }
            Self::TraceQueryDoesNotMatchCommitment => {
                write!(f, "failed to open trace query against the given commitment")
            }
            Self::ConstraintQueryDoesNotMatchCommitment => {
                write!(f, "failed to open constraint query against the given commitment")
            }
            Self::QuerySeedProofOfWorkVerificationFailed => {
                write!(f, "query seed proof-of-work verification failed")
            }
            Self::FriVerificationFailed(err) => {
                write!(f, "verification of low-degree proof failed: {err}")
            }
            Self::InsufficientConjecturedSecurity(minimal_security, proof_security)=> {
                write!(f, "insufficient proof security level: expected at least {minimal_security} bits of conjectured security, but was {proof_security} bits")
            }
            Self::InsufficientProvenSecurity(minimal_security, proof_security)=> {
                write!(f, "insufficient proof security level: expected at least {minimal_security} bits of proven security, but was {proof_security} bits")
            }
            Self::UnacceptableProofOptions => {write!(f, "invalid proof options: security parameters do not match the acceptable parameter set")}
        }
    }
}

impl core::error::Error for VerifierError {}
