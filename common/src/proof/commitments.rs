// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::ProofSerializationError;
use crypto::Hasher;
use serde::{Deserialize, Serialize};

// COMMITMENTS
// ================================================================================================

#[derive(Clone, Serialize, Deserialize)]
pub struct Commitments(Vec<u8>);

impl Commitments {
    /// Serializes the provided commitments into a vector of bytes.
    pub fn new<H: Hasher>(
        trace_root: H::Digest,
        constraint_root: H::Digest,
        fri_roots: Vec<H::Digest>,
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(trace_root.as_ref());
        bytes.extend_from_slice(constraint_root.as_ref());
        for fri_root in fri_roots.iter() {
            bytes.extend_from_slice(fri_root.as_ref());
        }
        Commitments(bytes)
    }

    /// Parses the serialized commitments into distinct parts.
    #[allow(clippy::type_complexity)]
    pub fn parse<H: Hasher>(
        self,
        num_fri_layers: usize,
    ) -> Result<(H::Digest, H::Digest, Vec<H::Digest>), ProofSerializationError> {
        let num_bytes = self.0.len();
        // +1 for trace_root, +1 for constraint root, + 1 for FRI remainder commitment
        let num_commitments = num_fri_layers + 3;
        let (commitments, read_bytes) = H::read_digests_into_vec(&self.0, num_commitments)
            .map_err(|err| ProofSerializationError::FailedToParseCommitments(err.to_string()))?;
        // make sure we consumed all available commitment bytes
        if read_bytes != num_bytes {
            return Err(ProofSerializationError::TooManyCommitmentBytes(
                read_bytes, num_bytes,
            ));
        }
        Ok((commitments[0], commitments[1], commitments[2..].to_vec()))
    }
}
