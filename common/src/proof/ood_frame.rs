// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{errors::ProofSerializationError, EvaluationFrame};
use math::{field::FieldElement, utils::read_elements_into_vec};
use serde::{Deserialize, Serialize};

// OUT-OF-DOMAIN EVALUATION FRAME
// ================================================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OodFrame {
    trace_at_z1: Vec<u8>,
    trace_at_z2: Vec<u8>,
    evaluations: Vec<u8>,
}

impl OodFrame {
    /// Serializes the provided evaluation frame and a vector of out-of-domain constraint
    /// evaluations into vectors of bytes.
    pub fn new<E: FieldElement>(frame: EvaluationFrame<E>, evaluations: Vec<E>) -> Self {
        OodFrame {
            trace_at_z1: E::elements_as_bytes(&frame.current).to_vec(),
            trace_at_z2: E::elements_as_bytes(&frame.next).to_vec(),
            evaluations: E::elements_as_bytes(&evaluations).to_vec(),
        }
    }

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
}
