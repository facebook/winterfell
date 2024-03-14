// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;
use math::FieldElement;
use utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};

// TYPE ALIASES
// ================================================================================================

type ParsedOodFrame<E> = (Vec<E>, Vec<E>);

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
    trace_states: Vec<u8>,
    evaluations: Vec<u8>,
}

impl OodFrame {
    // UPDATERS
    // --------------------------------------------------------------------------------------------

    /// Updates the trace state portion of this out-of-domain frame. This also returns a compacted
    /// version of the out-of-domain frame with the rows interleaved. This is done so that reseeding
    /// of the random coin needs to be done only once as opposed to once per each row.
    ///
    /// # Panics
    /// Panics if evaluation frame has already been set.
    pub fn set_trace_states<E: FieldElement>(&mut self, trace_states: &[Vec<E>]) -> Vec<E> {
        assert!(self.trace_states.is_empty(), "trace sates have already been set");

        // save the evaluations with the current and next evaluations interleaved for each polynomial
        let frame_size = trace_states.len();
        let width = trace_states[0].len();

        let mut result = vec![];
        for i in 0..width {
            for row in trace_states.iter() {
                result.push(row[i]);
            }
        }
        debug_assert!(frame_size <= u8::MAX as usize);
        self.trace_states.write_u8(frame_size as u8);
        self.trace_states.write_many(&result);

        result
    }

    /// Updates constraint evaluation portion of this out-of-domain frame.
    ///
    /// # Panics
    /// Panics if:
    /// * Constraint evaluations have already been set.
    /// * `evaluations` is an empty vector.
    pub fn set_constraint_evaluations<E: FieldElement>(&mut self, evaluations: &[E]) {
        assert!(self.evaluations.is_empty(), "constraint evaluations have already been set");
        assert!(!evaluations.is_empty(), "cannot set to empty constraint evaluations");
        self.evaluations.write_many(evaluations);
    }

    // PARSER
    // --------------------------------------------------------------------------------------------
    /// Returns main and auxiliary (if any) trace evaluation frames and a vector of out-of-domain
    /// constraint evaluations contained in `self`.
    ///
    /// # Panics
    /// Panics if either `main_trace_width` or `num_evaluations` are equal to zero.
    ///
    /// # Errors
    /// Returns an error if:
    /// * Valid [EvaluationFrame]s for the specified `main_trace_width` and `aux_trace_width`
    ///   could not be parsed from the internal bytes.
    /// * A vector of evaluations specified by `num_evaluations` could not be parsed from the
    ///   internal bytes.
    /// * Any unconsumed bytes remained after the parsing was complete.
    pub fn parse<E: FieldElement>(
        self,
        main_trace_width: usize,
        aux_trace_width: usize,
        num_evaluations: usize,
    ) -> Result<ParsedOodFrame<E>, DeserializationError> {
        assert!(main_trace_width > 0, "trace width cannot be zero");
        assert!(num_evaluations > 0, "number of evaluations cannot be zero");

        // parse main and auxiliary trace evaluation frames
        let mut reader = SliceReader::new(&self.trace_states);
        let frame_size = reader.read_u8()? as usize;
        let trace = reader.read_many((main_trace_width + aux_trace_width) * frame_size)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        // parse the constraint evaluations
        let mut reader = SliceReader::new(&self.evaluations);
        let evaluations = reader.read_many(num_evaluations)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        Ok((trace, evaluations))
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for OodFrame {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write trace rows
        target.write_u16(self.trace_states.len() as u16);
        target.write_bytes(&self.trace_states);

        // write constraint evaluations row
        target.write_u16(self.evaluations.len() as u16);
        target.write_bytes(&self.evaluations)
    }

    /// Returns an estimate of how many bytes are needed to represent self.
    fn get_size_hint(&self) -> usize {
        self.trace_states.len() + self.evaluations.len() + 4
    }
}

impl Deserializable for OodFrame {
    /// Reads a OOD frame from the specified `source` and returns the result
    ///
    /// # Errors
    /// Returns an error of a valid OOD frame could not be read from the specified `source`.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // read trace rows
        let num_trace_state_bytes = source.read_u16()? as usize;
        let trace_states = source.read_vec(num_trace_state_bytes)?;

        // read constraint evaluations row
        let num_constraint_evaluation_bytes = source.read_u16()? as usize;
        let evaluations = source.read_vec(num_constraint_evaluation_bytes)?;

        Ok(OodFrame {
            trace_states,
            evaluations,
        })
    }
}
