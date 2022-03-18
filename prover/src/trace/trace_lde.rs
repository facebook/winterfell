// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Matrix;
use air::{proof::Queries, EvaluationFrame};
use crypto::{ElementHasher, Hasher, MerkleTree};
use math::StarkField;
use utils::collections::Vec;

// TRACE LDE
// ================================================================================================

/// Trace low-degree extension.
pub struct TraceLde<B: StarkField> {
    data: Matrix<B>,
    blowup: usize,
}

impl<B: StarkField> TraceLde<B> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new trace low-degree extension from a list of provided columns.
    pub fn new(data: Matrix<B>, blowup: usize) -> Self {
        TraceLde { data, blowup }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in this trace LDE.
    pub fn width(&self) -> usize {
        self.data.num_cols()
    }

    /// Returns the number of rows in this trace LDE.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.num_rows()
    }

    /// Returns blowup factor which was used to extend original execution trace into this LDE.
    pub fn blowup(&self) -> usize {
        self.blowup
    }

    /// Returns value of a trace cell in the column at the specified index at the specified step.
    pub fn get(&self, col_idx: usize, step: usize) -> B {
        self.data.get_column(col_idx)[step]
    }

    /// Returns the entire trace for the column at the specified index.
    #[cfg(test)]
    pub fn get_column(&self, col_idx: usize) -> &[B] {
        self.data.get_column(col_idx)
    }

    /// Copies values of all columns at the specified `step` into the `destination` slice.
    pub fn read_row_into(&self, step: usize, row: &mut [B]) {
        self.data.read_row_into(step, row)
    }

    /// Reads current and next rows from the execution trace table into the specified frame.
    pub fn read_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<B>) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.len();

        self.read_row_into(lde_step, frame.current_mut());
        self.read_row_into(next_lde_step, frame.next_mut());
    }

    // TRACE COMMITMENT
    // --------------------------------------------------------------------------------------------
    /// Builds a Merkle tree out of trace table rows (hash of each row becomes a leaf in the tree).
    pub fn build_commitment<H: ElementHasher<BaseField = B>>(&self) -> MerkleTree<H> {
        self.data.commit_to_rows()
    }

    // QUERY TRACE
    // --------------------------------------------------------------------------------------------
    /// Returns trace table rows at the specified positions along with Merkle authentication paths
    /// from the `commitment` root to these rows.
    pub fn query<H: Hasher>(&self, commitment: MerkleTree<H>, positions: &[usize]) -> Queries {
        assert_eq!(
            self.len(),
            commitment.leaves().len(),
            "inconsistent trace table commitment"
        );

        // allocate memory for queried trace states
        let mut trace_states = Vec::with_capacity(positions.len());

        // copy values from the trace table at the specified positions into rows
        // and append the rows to trace_states
        for &i in positions.iter() {
            let row = self.data.columns().map(|column| column[i]).collect();
            trace_states.push(row);
        }

        // build Merkle authentication paths to the leaves specified by positions
        let trace_proof = commitment
            .prove_batch(positions)
            .expect("failed to generate a Merkle proof for trace queries");

        Queries::new(trace_proof, trace_states)
    }
}
