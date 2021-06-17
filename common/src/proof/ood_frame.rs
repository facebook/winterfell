// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{errors::ProofSerializationError, EvaluationFrame};
use math::{field::FieldElement, utils::read_elements_into_vec};
use utils::{read_u16, read_u8_vec, DeserializationError};

// OUT-OF-DOMAIN EVALUATION FRAME
// ================================================================================================

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OodFrame {
    trace_at_z1: Vec<u8>,
    trace_at_z2: Vec<u8>,
    evaluations: Vec<u8>,
}

impl OodFrame {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Serializes the provided evaluation frame and a vector of out-of-domain constraint
    /// evaluations into vectors of bytes.
    pub fn new<E: FieldElement>(frame: EvaluationFrame<E>, evaluations: Vec<E>) -> Self {
        let mut result = Self::default();
        result.set_evaluation_frame(&frame);
        result.set_constraint_evaluations(&evaluations);
        result
    }

    // UPDATERS
    // --------------------------------------------------------------------------------------------

    /// Updates this evaluation frame potion of this out-of-domain frame.
    pub fn set_evaluation_frame<E: FieldElement>(&mut self, frame: &EvaluationFrame<E>) {
        assert!(self.trace_at_z1.is_empty());
        assert!(self.trace_at_z2.is_empty());
        E::write_batch_into(&frame.current, &mut self.trace_at_z1);
        E::write_batch_into(&frame.next, &mut self.trace_at_z2);
    }

    pub fn set_constraint_evaluations<E: FieldElement>(&mut self, evaluations: &[E]) {
        assert!(self.evaluations.is_empty());
        E::write_batch_into(evaluations, &mut self.evaluations);
    }

    // PARSER
    // --------------------------------------------------------------------------------------------
    /// Returns an evaluation frame and a vector of out-of-domain constraint evaluations parsed
    /// from the serialized byte vectors.
    pub fn parse<E: FieldElement>(
        self,
        trace_width: usize,
        num_evaluations: usize,
    ) -> Result<(EvaluationFrame<E>, Vec<E>), ProofSerializationError> {
        let current = read_elements_into_vec(&self.trace_at_z1)
            .map_err(|err| ProofSerializationError::FailedToParseOodFrame(err.to_string()))?;
        if current.len() != trace_width {
            return Err(ProofSerializationError::WrongNumberOfOodTraceElements(
                trace_width,
                current.len(),
            ));
        }

        let next = read_elements_into_vec(&self.trace_at_z2)
            .map_err(|err| ProofSerializationError::FailedToParseOodFrame(err.to_string()))?;
        if next.len() != trace_width {
            return Err(ProofSerializationError::WrongNumberOfOodTraceElements(
                trace_width,
                next.len(),
            ));
        }

        let evaluations = read_elements_into_vec(&self.evaluations)
            .map_err(|err| ProofSerializationError::FailedToParseOodFrame(err.to_string()))?;
        if evaluations.len() != num_evaluations {
            return Err(ProofSerializationError::WrongNumberOfOodEvaluationElements(
                num_evaluations,
                evaluations.len(),
            ));
        }

        Ok((EvaluationFrame { current, next }, evaluations))
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this out-of-domain frame and appends the resulting bytes to the `target` vector.
    pub fn write_into(&self, target: &mut Vec<u8>) {
        // write trace rows (both rows have the same number of bytes)
        target.extend_from_slice(&(self.trace_at_z1.len() as u16).to_le_bytes());
        target.extend_from_slice(&self.trace_at_z1);
        target.extend_from_slice(&self.trace_at_z2);

        // write constraint evaluations row
        target.extend_from_slice(&(self.evaluations.len() as u16).to_le_bytes());
        target.extend_from_slice(&self.evaluations)
    }

    /// Reads a OOD frame from the specified source starting at the specified position and
    /// increments `pos` to point to a position right after the end of read-in frame bytes.
    /// Returns an error of a valid OOD frame could not be read from the specified source.
    pub fn read_from(source: &[u8], pos: &mut usize) -> Result<Self, DeserializationError> {
        // read trace rows
        let trace_row_bytes = read_u16(source, pos)? as usize;
        let trace_at_z1 = read_u8_vec(source, pos, trace_row_bytes)?;
        let trace_at_z2 = read_u8_vec(source, pos, trace_row_bytes)?;

        // read constraint evaluations row
        let constraint_row_bytes = read_u16(source, pos)? as usize;
        let evaluations = read_u8_vec(source, pos, constraint_row_bytes)?;

        Ok(OodFrame {
            trace_at_z1,
            trace_at_z2,
            evaluations,
        })
    }
}

impl Default for OodFrame {
    fn default() -> Self {
        OodFrame {
            trace_at_z1: Vec::new(),
            trace_at_z2: Vec::new(),
            evaluations: Vec::new(),
        }
    }
}
