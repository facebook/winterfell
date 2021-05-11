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
pub struct OodEvaluationFrame {
    trace_at_z1: Vec<u8>,
    trace_at_z2: Vec<u8>,
}

impl OodEvaluationFrame {
    /// Serializes the provided evaluation frame into vectors of bytes.
    pub fn new<E: FieldElement>(frame: EvaluationFrame<E>) -> Self {
        OodEvaluationFrame {
            trace_at_z1: E::elements_as_bytes(&frame.current).to_vec(),
            trace_at_z2: E::elements_as_bytes(&frame.next).to_vec(),
        }
    }

    /// Returns an evaluation frame parsed from the serialized byte vectors.
    pub fn parse<E: FieldElement>(
        self,
        trace_width: usize,
    ) -> Result<EvaluationFrame<E>, ProofSerializationError> {
        let current = read_elements_into_vec(&self.trace_at_z1)
            .map_err(|err| ProofSerializationError::FailedToParseOodFrame(err.to_string()))?;
        if current.len() != trace_width {
            return Err(ProofSerializationError::TooManyOodFrameElements(
                trace_width,
                current.len(),
            ));
        }

        let next = read_elements_into_vec(&self.trace_at_z2)
            .map_err(|err| ProofSerializationError::FailedToParseOodFrame(err.to_string()))?;
        if next.len() != trace_width {
            return Err(ProofSerializationError::TooManyOodFrameElements(
                trace_width,
                next.len(),
            ));
        }

        Ok(EvaluationFrame { current, next })
    }
}
