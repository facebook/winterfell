// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::vec::Vec;

use crypto::ElementHasher;
use math::FieldElement;
use utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
};

use crate::EvaluationFrame;

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

    /// Updates the trace state portion of this out-of-domain frame, and returns the hash of the
    /// trace states.
    ///
    /// The out-of-domain frame is stored as one vector built from the concatenation of values of
    /// two vectors, the current row vector and the next row vector. Given the input frame
    ///
    ///    +-------+-------+-------+-------+-------+-------+-------+-------+
    ///    |   a1  |   a2  |  ...  |  an   |  c1   |  c2   |  ...  |  cm   |
    ///    +-------+-------+-------+-------+-------+-------+-------+-------+
    ///    |   b1  |   b2  |  ...  |  bn   |  d1   |  d2   |  ...  |  dm   |
    ///    +-------+-------+-------+-------+-------+-------+-------+-------+
    ///
    /// with n being the main trace width and m the auxiliary trace width, the values are stored as
    ///
    /// [a1, ..., an, c1, ..., cm, b1, ..., bn, d1, ..., dm]
    ///
    /// into `Self::trace_states` (as byte values).
    ///
    /// # Panics
    /// Panics if evaluation frame has already been set.
    pub fn set_trace_states<E, H>(&mut self, trace_ood_frame: &TraceOodFrame<E>) -> H::Digest
    where
        E: FieldElement,
        H: ElementHasher<BaseField = E::BaseField>,
    {
        assert!(self.trace_states.is_empty(), "trace sates have already been set");

        // save the evaluations of the current and then next evaluations for each polynomial
        let main_and_aux_trace_states = trace_ood_frame.to_trace_states();

        // there are 2 frames: current and next
        let frame_size: u8 = 2;
        self.trace_states.write_u8(frame_size);
        self.trace_states.write_many(&main_and_aux_trace_states);

        H::hash_elements(&main_and_aux_trace_states)
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
    /// Returns an out-of-domain trace frame and a vector of out-of-domain constraint evaluations
    /// contained in `self`.
    ///
    /// # Panics
    /// Panics if either `main_trace_width` or `num_evaluations` are equal to zero.
    ///
    /// # Errors
    /// Returns an error if:
    /// * Valid [`crate::EvaluationFrame`]s for the specified `main_trace_width` and
    ///   `aux_trace_width` could not be parsed from the internal bytes.
    /// * A vector of evaluations specified by `num_evaluations` could not be parsed from the
    ///   internal bytes.
    /// * Any unconsumed bytes remained after the parsing was complete.
    pub fn parse<E: FieldElement>(
        self,
        main_trace_width: usize,
        aux_trace_width: usize,
        num_evaluations: usize,
    ) -> Result<(TraceOodFrame<E>, Vec<E>), DeserializationError> {
        assert!(main_trace_width > 0, "trace width cannot be zero");
        assert!(num_evaluations > 0, "number of evaluations cannot be zero");

        // parse main and auxiliary trace evaluation frames. This does the reverse operation done in
        // `set_trace_states()`.
        let (current_row, next_row) = {
            let mut reader = SliceReader::new(&self.trace_states);
            let frame_size = reader.read_u8()? as usize;
            let mut trace = reader.read_many((main_trace_width + aux_trace_width) * frame_size)?;

            if reader.has_more_bytes() {
                return Err(DeserializationError::UnconsumedBytes);
            }

            let next_row = trace.split_off(main_trace_width + aux_trace_width);
            let current_row = trace;
            (current_row, next_row)
        };

        // parse the constraint evaluations
        let mut reader = SliceReader::new(&self.evaluations);
        let evaluations = reader.read_many(num_evaluations)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::UnconsumedBytes);
        }

        Ok((TraceOodFrame::new(current_row, next_row, main_trace_width), evaluations))
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

        Ok(OodFrame { trace_states, evaluations })
    }
}

// OOD FRAME TRACE STATES
// ================================================================================================

/// Trace evaluation frame at the out-of-domain point.
///
/// Stores the trace evaluations at `z` and `gz`, where `z` is a random Field element in
/// `current_row` and `next_row`, respectively.
pub struct TraceOodFrame<E: FieldElement> {
    current_row: Vec<E>,
    next_row: Vec<E>,
    main_trace_width: usize,
}

impl<E: FieldElement> TraceOodFrame<E> {
    /// Creates a new [`TraceOodFrame`] from current, next.
    pub fn new(current_row: Vec<E>, next_row: Vec<E>, main_trace_width: usize) -> Self {
        assert_eq!(current_row.len(), next_row.len());

        Self { current_row, next_row, main_trace_width }
    }

    /// Returns the number of columns for the current and next frames.
    pub fn num_columns(&self) -> usize {
        self.current_row.len()
    }

    /// Returns the current row, consisting of both main and auxiliary columns.
    pub fn current_row(&self) -> &[E] {
        &self.current_row
    }

    /// Returns the next frame, consisting of both main and auxiliary columns.
    pub fn next_row(&self) -> &[E] {
        &self.next_row
    }

    /// Returns the evaluation frame for the main trace
    pub fn main_frame(&self) -> EvaluationFrame<E> {
        let current = self.current_row[0..self.main_trace_width].to_vec();
        let next = self.next_row[0..self.main_trace_width].to_vec();

        EvaluationFrame::from_rows(current, next)
    }

    /// Returns the evaluation frame for the auxiliary trace
    pub fn aux_frame(&self) -> Option<EvaluationFrame<E>> {
        if self.has_aux_frame() {
            let current = self.current_row[self.main_trace_width..].to_vec();
            let next = self.next_row[self.main_trace_width..].to_vec();

            Some(EvaluationFrame::from_rows(current, next))
        } else {
            None
        }
    }

    /// Hashes the main, auxiliary frames in a manner consistent with
    /// [`OodFrame::set_trace_states`], with the purpose of reseeding the public coin.
    pub fn hash<H: ElementHasher<BaseField = E::BaseField>>(&self) -> H::Digest {
        let trace_states = self.to_trace_states();

        H::hash_elements(&trace_states)
    }

    /// Returns true if an auxiliary frame is present
    fn has_aux_frame(&self) -> bool {
        self.current_row.len() > self.main_trace_width
    }

    /// Returns the main/aux frames as a vector of elements described in
    /// [`OodFrame::set_trace_states`].
    fn to_trace_states(&self) -> Vec<E> {
        let mut main_and_aux_frame_states = Vec::new();
        main_and_aux_frame_states.extend_from_slice(&self.current_row);
        main_and_aux_frame_states.extend_from_slice(&self.next_row);

        main_and_aux_frame_states
    }
}
