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

// TYPE ALIASES
// ================================================================================================

type ParsedOodFrame<E> = (EvaluationFrame<E>, Option<EvaluationFrame<E>>, Vec<E>);

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

    /// Updates the trace state portion of this out-of-domain frame.
    ///
    /// # Panics
    /// Panics if evaluation frame has already been set.
    pub fn set_trace_states<E: FieldElement>(&mut self, trace_states: &[Vec<E>]) {
        assert!(
            self.trace_states.is_empty(),
            "trace sates have already been set"
        );
        for trace_state in trace_states {
            trace_state.write_into(&mut self.trace_states);
        }
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

        // parse current and next trace states for main and auxiliary trace evaluation frames
        let mut reader = SliceReader::new(&self.trace_states);
        let current = E::read_batch_from(&mut reader, main_trace_width)?;
        let current_aux = E::read_batch_from(&mut reader, aux_trace_width)?;
        let next = E::read_batch_from(&mut reader, main_trace_width)?;
        let next_aux = E::read_batch_from(&mut reader, aux_trace_width)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        // instantiate the frames from the parsed rows
        let main_frame = EvaluationFrame::from_rows(current, next);
        let aux_frame = if aux_trace_width > 0 {
            Some(EvaluationFrame::from_rows(current_aux, next_aux))
        } else {
            None
        };

        // parse the constraint evaluations
        let mut reader = SliceReader::new(&self.evaluations);
        let evaluations = E::read_batch_from(&mut reader, num_evaluations)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        Ok((main_frame, aux_frame, evaluations))
    }
}

impl Serializable for OodFrame {
    /// Serializes `self` and writes the resulting bytes into the `target`.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // write trace rows
        target.write_u16(self.trace_states.len() as u16);
        target.write_u8_slice(&self.trace_states);

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
        let num_trace_state_bytes = source.read_u16()? as usize;
        let trace_states = source.read_u8_vec(num_trace_state_bytes)?;

        // read constraint evaluations row
        let num_constraint_evaluation_bytes = source.read_u16()? as usize;
        let evaluations = source.read_u8_vec(num_constraint_evaluation_bytes)?;

        Ok(OodFrame {
            trace_states,
            evaluations,
        })
    }
}
