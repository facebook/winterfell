// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Matrix;
use air::{proof::Queries, EvaluationFrame};
use crypto::{ElementHasher, MerkleTree};
use math::StarkField;
use utils::collections::Vec;

// TRACE COMMITMENT
// ================================================================================================

/// Execution trace commitment.
///
/// The commitment consists of two components:
/// * Evaluations of trace polynomials over the LDE domain.
/// * Merkle tree where each leaf in the tree corresponds to a row in the trace LDE matrix.
pub struct TraceCommitment<B: StarkField, H: ElementHasher<BaseField = B>> {
    trace_lde: Matrix<B>,
    commitment: MerkleTree<H>,
    blowup: usize,
}

impl<B: StarkField, H: ElementHasher<BaseField = B>> TraceCommitment<B, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new trace commitment from the provided trace low-degree extension and the
    /// corresponding Merkle tree commitment.
    pub fn new(trace_lde: Matrix<B>, commitment: MerkleTree<H>, blowup: usize) -> Self {
        assert_eq!(
            trace_lde.num_rows(),
            commitment.leaves().len(),
            "number of rows in trace LDE must be the same as number of leaves in trace commitment"
        );
        Self {
            trace_lde,
            commitment,
            blowup,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in the execution trace.
    pub fn trace_width(&self) -> usize {
        self.trace_lde.num_cols()
    }

    /// Returns the number of rows in the execution trace.
    pub fn trace_len(&self) -> usize {
        self.trace_lde.num_rows()
    }

    /// Returns blowup factor which was used to extend original execution trace into trace LDE.
    pub fn blowup(&self) -> usize {
        self.blowup
    }

    /// Returns the root of the commitment Merkle tree.
    pub fn root(&self) -> H::Digest {
        *self.commitment.root()
    }

    /// Reads current and next rows from the execution trace table into the specified frame.
    pub fn read_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<B>) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.trace_len();

        self.trace_lde.read_row_into(lde_step, frame.current_mut());
        self.trace_lde
            .read_row_into(next_lde_step, frame.next_mut());
    }

    // QUERY TRACE
    // --------------------------------------------------------------------------------------------
    /// Returns trace table rows at the specified positions along with Merkle authentication paths
    /// from the commitment root to these rows.
    pub fn query(&self, positions: &[usize]) -> Queries {
        // allocate memory for queried trace states
        let mut trace_states = Vec::with_capacity(positions.len());

        // copy values from the trace table at the specified positions into rows
        // and append the rows to trace_states
        for &i in positions.iter() {
            let row = self.trace_lde.columns().map(|column| column[i]).collect();
            trace_states.push(row);
        }

        // build Merkle authentication paths to the leaves specified by positions
        let trace_proof = self
            .commitment
            .prove_batch(positions)
            .expect("failed to generate a Merkle proof for trace queries");

        Queries::new(trace_proof, trace_states)
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the entire trace for the column at the specified index.
    #[cfg(test)]
    pub fn get_trace_column(&self, col_idx: usize) -> &[B] {
        self.trace_lde.get_column(col_idx)
    }

    /// Returns value of a trace cell in the column at the specified index at the specified step.
    #[cfg(test)]
    pub fn get_trace_cell(&self, col_idx: usize, step: usize) -> B {
        self.trace_lde.get(col_idx, step)
    }
}
