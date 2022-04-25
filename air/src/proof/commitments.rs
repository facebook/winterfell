// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crypto::Hasher;
use utils::{
    collections::Vec, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    SliceReader,
};

// COMMITMENTS
// ================================================================================================
/// Commitments made by the prover during commit phase of the protocol.
///
/// These commitments include:
/// * Commitment to the extended execution trace, which may include commitments to one or more
///   execution trace segments.
/// * Commitment to the evaluations of constraint composition polynomial over LDE domain.
/// * Commitments to the evaluations of polynomials at all FRI layers.
///
/// Internally, the commitments are stored as a sequence of bytes. Thus, to retrieve the
/// commitments, [parse()](Commitments::parse) function should be used.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Commitments(Vec<u8>);

impl Commitments {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new Commitments struct initialized with the provided commitments.
    pub fn new<H: Hasher>(
        trace_roots: Vec<H::Digest>,
        constraint_root: H::Digest,
        fri_roots: Vec<H::Digest>,
    ) -> Self {
        let mut bytes = Vec::new();
        bytes.write(trace_roots);
        bytes.write(constraint_root);
        bytes.write(fri_roots);
        Commitments(bytes)
    }

    // PUBLIC METHODS
    // --------------------------------------------------------------------------------------------

    /// Adds the specified commitment to the list of commitments.
    pub fn add<H: Hasher>(&mut self, commitment: &H::Digest) {
        commitment.write_into(&mut self.0);
    }

    // PARSING
    // --------------------------------------------------------------------------------------------

    /// Parses the serialized commitments into distinct parts.
    ///
    /// The parts are (in the order in which they appear in the tuple):
    /// 1. Extended execution trace commitments.
    /// 2. Constraint composition polynomial evaluation commitment.
    /// 3. FRI layer commitments.
    ///
    /// # Errors
    /// Returns an error if the bytes stored in self could not be parsed into the requested number
    /// of commitments, or if there are any unconsumed bytes remaining after the parsing completes.
    #[allow(clippy::type_complexity)]
    pub fn parse<H: Hasher>(
        self,
        num_trace_segments: usize,
        num_fri_layers: usize,
    ) -> Result<(Vec<H::Digest>, H::Digest, Vec<H::Digest>), DeserializationError> {
        let mut reader = SliceReader::new(&self.0);

        // parse trace commitments
        let trace_commitments = H::Digest::read_batch_from(&mut reader, num_trace_segments)?;

        // parse constraint evaluation commitment:
        let constraint_commitment = H::Digest::read_from(&mut reader)?;

        // read FRI commitments (+1 is for FRI remainder commitment)
        let fri_commitments = H::Digest::read_batch_from(&mut reader, num_fri_layers + 1)?;

        // make sure we consumed all available commitment bytes
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }
        Ok((trace_commitments, constraint_commitment, fri_commitments))
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
