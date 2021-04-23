// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("FRI queries did not match the commitment at layer {0}")]
    LayerCommitmentMismatch(usize),

    #[error("FRI queries at layer {0} could not be deserialized: {1}")]
    LayerDeserializationError(usize, String),

    #[error("FRI evaluations did not match query values at depth {0}")]
    LayerValuesNotConsistent(usize),

    #[error("FRI remainder did not match the commitment")]
    RemainderCommitmentMismatch,

    #[error("FRI remainder could not be deserialized: {0}")]
    RemainderDeserializationError(String),

    #[error("FRI remainder values are inconsistent with values of the last column")]
    RemainderValuesNotConsistent,

    #[error("FRI remainder degree is greater than number of remainder values")]
    RemainderDegreeNotValid,

    #[error("FRI remainder is not a valid degree {0} polynomial")]
    RemainderDegreeMismatch(usize),
}
