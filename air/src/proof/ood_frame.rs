// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::EvaluationFrame;
use math::FieldElement;
use utils::{
    collections::Vec, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    SliceReader,
};

// OUT-OF-DOMAIN FRAME
// ================================================================================================
/// Trace and constraint polynomial evaluations at an out-of-domain point.
///
/// This struct contains the following evaluations:
/// * Evaluations of all trace polynomials at *z*.
/// * Evaluations of all trace polynomials at *z * g*.
/// * Evaluations of constraint composition column polynomials at *z*.
///
/// where *z* is an out-of-domain point and *g* is the generator of the trace domain.
///
/// Internally, the evaluations are stored as a sequence of bytes. Thus, to retrieve the
/// evaluations, [parse()](OodFrame::parse) function should be used.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OodFrame {
    trace_at_z1: Vec<u8>,
    trace_at_z2: Vec<u8>,
    evaluations: Vec<u8>,
}

impl OodFrame {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [OodFrame] instantiated with the provided evaluation frame and a vector of
    /// out-of-domain constraint evaluations.
    ///
    /// # Panics
    /// Panics if `evaluations` is an empty vector.
    pub fn new<E: FieldElement>(frame: EvaluationFrame<E>, evaluations: Vec<E>) -> Self {
        let mut result = Self::default();
        result.set_evaluation_frame(&frame);
        result.set_constraint_evaluations(&evaluations);
        result
    }

    // UPDATERS
    // --------------------------------------------------------------------------------------------

    /// Updates evaluation frame portion of this out-of-domain frame.
    ///
    /// # Panics
    /// Panics if evaluation frame has already been set.
    pub fn set_evaluation_frame<E: FieldElement>(&mut self, frame: &EvaluationFrame<E>) {
        assert!(
            self.trace_at_z1.is_empty(),
            "evaluation frame has already been set"
        );
        assert!(
            self.trace_at_z2.is_empty(),
            "evaluation frame has already been set"
        );
        frame.current().write_into(&mut self.trace_at_z1);
        frame.next().write_into(&mut self.trace_at_z2);
    }

    /// Updates constraint evaluation portion of this out-of-domain frame.
    ///
    /// # Panics
    /// Panics if:
    /// * Constraint evaluations have already been set.
    /// * `evaluations` is an empty vector.
    pub fn set_constraint_evaluations<E: FieldElement>(&mut self, evaluations: &[E]) {
        assert!(
            self.evaluations.is_empty(),
            "constraint evaluations have already been set"
        );
        assert!(
            !evaluations.is_empty(),
            "cannot set to empty constraint evaluations"
        );
        evaluations.write_into(&mut self.evaluations)
    }

    // PARSER
    // --------------------------------------------------------------------------------------------
    /// Returns an evaluation frame and a vector of out-of-domain constraint evaluations contained
    /// in `self`.
    ///
    /// # Panics
    /// Panics if either `trace_width` or `num_evaluations` are equal to zero.
    ///
    /// # Errors
    /// Returns an error if:
    /// * A valid [EvaluationFrame] for the specified `trace_width` could not be parsed from the
    ///   internal bytes.
    /// * A vector of evaluations specified by `num_evaluations` could not be parsed from the
    ///   internal bytes.
    /// * Any unconsumed bytes remained after the parsing was complete.
    pub fn parse<E: FieldElement>(
        self,
        trace_width: usize,
        num_evaluations: usize,
    ) -> Result<(EvaluationFrame<E>, Vec<E>), DeserializationError> {
        assert!(trace_width > 0, "trace width cannot be zero");
        assert!(num_evaluations > 0, "number of evaluations cannot be zero");

        let mut reader = SliceReader::new(&self.trace_at_z1);
        let current = E::read_batch_from(&mut reader, trace_width)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        let mut reader = SliceReader::new(&self.trace_at_z2);
        let next = E::read_batch_from(&mut reader, trace_width)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        let mut reader = SliceReader::new(&self.evaluations);
        let evaluations = E::read_batch_from(&mut reader, num_evaluations)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        Ok((EvaluationFrame::from_rows(current, next), evaluations))
    }
}

impl Serializable for OodFrame {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write trace rows (both rows have the same number of bytes)
        target.write_u16(self.trace_at_z1.len() as u16);
        target.write_u8_slice(&self.trace_at_z1);
        target.write_u8_slice(&self.trace_at_z2);

        // write constraint evaluations row
        target.write_u16(self.evaluations.len() as u16);
        target.write_u8_slice(&self.evaluations)
    }
}

impl Deserializable for OodFrame {
    /// Reads a OOD frame from the specified `source` and returns the result
    ///
    /// # Errors
    /// Returns an error of a valid OOD frame could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // read trace rows
        let trace_row_bytes = source.read_u16()? as usize;
        let trace_at_z1 = source.read_u8_vec(trace_row_bytes)?;
        let trace_at_z2 = source.read_u8_vec(trace_row_bytes)?;

        // read constraint evaluations row
        let constraint_row_bytes = source.read_u16()? as usize;
        let evaluations = source.read_u8_vec(constraint_row_bytes)?;

        Ok(OodFrame {
            trace_at_z1,
            trace_at_z2,
            evaluations,
        })
    }
}
