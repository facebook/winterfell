// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::errors::ProofSerializationError;
use crypto::Hasher;
use utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};

// COMMITMENTS
// ================================================================================================

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Commitments(Vec<u8>);

impl Commitments {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new Commitments struct initialized with the provided commitments.
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

    // PUBLIC METHODS
    // --------------------------------------------------------------------------------------------

    /// Adds the specified commitment to the list of commitments.
    pub fn add<H: Hasher>(&mut self, commitment: &H::Digest) {
        self.0.extend_from_slice(commitment.as_ref())
    }

    // PARSING
    // --------------------------------------------------------------------------------------------

    /// Parses the serialized commitments into distinct parts.
    #[allow(clippy::type_complexity)]
    pub fn parse<H: Hasher>(
        self,
        num_fri_layers: usize,
    ) -> Result<(H::Digest, H::Digest, Vec<H::Digest>), ProofSerializationError> {
        // +1 for trace_root, +1 for constraint root, +1 for FRI remainder commitment
        let num_commitments = num_fri_layers + 3;
        let mut reader = SliceReader::new(&self.0);
        let commitments = H::Digest::read_batch_from(&mut reader, num_commitments)
            .map_err(|err| ProofSerializationError::FailedToParseCommitments(err.to_string()))?;
        // make sure we consumed all available commitment bytes
        if reader.has_more_bytes() {
            return Err(ProofSerializationError::TooManyCommitmentBytes);
        }
        Ok((commitments[0], commitments[1], commitments[2..].to_vec()))
    }
}

impl Default for Commitments {
    fn default() -> Self {
        Commitments(Vec::new())
    }
}

impl Serializable for Commitments {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        assert!(self.0.len() < u16::MAX as usize);
        target.write_u16(self.0.len() as u16);
        target.write_u8_slice(&self.0);
    }
}

impl Deserializable for Commitments {
    /// Reads commitments from the specified `source` and returns the result.
    ///
    /// # Errors
    /// Returns an error of a valid Commitments struct could not be read from the specified
    /// `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let num_bytes = source.read_u16()? as usize;
        let result = source.read_u8_vec(num_bytes)?;
        Ok(Commitments(result))
    }
}
