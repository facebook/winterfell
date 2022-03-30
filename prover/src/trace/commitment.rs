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
/// The described one or more trace segments, each consisting of the following components:
/// * Evaluations of a trace segment's polynomials over the LDE domain.
/// * Merkle tree where each leaf in the tree corresponds to a row in the trace LDE matrix.
pub struct TraceCommitment<B: StarkField, H: ElementHasher<BaseField = B>> {
    main_segment_lde: Matrix<B>,
    main_segment_tree: MerkleTree<H>,
    aux_segment_ldes: Vec<Matrix<B>>,
    aux_segment_trees: Vec<MerkleTree<H>>,
    blowup: usize,
}

impl<B: StarkField, H: ElementHasher<BaseField = B>> TraceCommitment<B, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new trace commitment from the provided main trace low-degree extension and the
    /// corresponding Merkle tree commitment.
    pub fn new(main_trace_lde: Matrix<B>, main_trace_tree: MerkleTree<H>, blowup: usize) -> Self {
        assert_eq!(
            main_trace_lde.num_rows(),
            main_trace_tree.leaves().len(),
            "number of rows in trace LDE must be the same as number of leaves in trace commitment"
        );
        Self {
            main_segment_lde: main_trace_lde,
            main_segment_tree: main_trace_tree,
            aux_segment_ldes: Vec::new(),
            aux_segment_trees: Vec::new(),
            blowup,
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided auxiliary segment trace LDE and Merkle tree to this trace commitment.
    pub fn add_segment(&mut self, aux_segment_lde: Matrix<B>, aux_segment_tree: MerkleTree<H>) {
        assert_eq!(
            aux_segment_lde.num_rows(),
            self.main_segment_lde.num_rows(),
            "auxiliary segment LDE length must be the same as the main segment LDE length"
        );
        assert_eq!(
            aux_segment_lde.num_rows(),
            aux_segment_tree.leaves().len(),
            "number of rows in trace LDE must be the same as number of leaves in trace commitment"
        );

        self.aux_segment_ldes.push(aux_segment_lde);
        self.aux_segment_trees.push(aux_segment_tree);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns number of columns in the execution trace.
    pub fn trace_width(&self) -> usize {
        self.main_segment_lde.num_cols()
            + self
                .aux_segment_ldes
                .iter()
                .fold(0, |s, m| s + m.num_cols())
    }

    /// Returns the number of rows in the execution trace.
    pub fn trace_len(&self) -> usize {
        self.main_segment_lde.num_rows()
    }

    /// Returns blowup factor which was used to extend original execution trace into trace LDE.
    pub fn blowup(&self) -> usize {
        self.blowup
    }

    /// Reads current and next rows from the execution trace table into the specified frame.
    pub fn read_frame_into(&self, lde_step: usize, frame: &mut EvaluationFrame<B>) {
        // at the end of the trace, next state wraps around and we read the first step again
        let next_lde_step = (lde_step + self.blowup()) % self.trace_len();

        // copy main trace segment values into the frame
        self.main_segment_lde
            .read_row_into(lde_step, frame.current_mut());
        self.main_segment_lde
            .read_row_into(next_lde_step, frame.next_mut());

        // copy auxiliary trace segment values into the frame
        let mut offset = self.main_segment_lde.num_cols();
        for segment in self.aux_segment_ldes.iter() {
            segment.read_row_into(lde_step, &mut frame.current_mut()[offset..]);
            segment.read_row_into(next_lde_step, &mut frame.next_mut()[offset..]);
            offset += segment.num_cols();
        }
    }

    // QUERY TRACE
    // --------------------------------------------------------------------------------------------
    /// Returns trace table rows at the specified positions along with Merkle authentication paths
    /// from the commitment root to these rows.
    pub fn query(&self, positions: &[usize]) -> Vec<Queries> {
        // build queries for the main trace segment
        let mut result = vec![build_segment_queries(
            &self.main_segment_lde,
            &self.main_segment_tree,
            positions,
        )];

        // build queries for auxiliary trace segments
        for (segment_lde, segment_tree) in self
            .aux_segment_ldes
            .iter()
            .zip(self.aux_segment_trees.iter())
        {
            result.push(build_segment_queries(segment_lde, segment_tree, positions));
        }

        result
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the commitment Merkle tree.
    #[cfg(test)]
    pub fn main_trace_root(&self) -> H::Digest {
        *self.main_segment_tree.root()
    }

    /// Returns the entire trace for the column at the specified index.
    #[cfg(test)]
    pub fn get_main_trace_column(&self, col_idx: usize) -> &[B] {
        self.main_segment_lde.get_column(col_idx)
    }

    /// Returns value of a trace cell in the column at the specified index at the specified step.
    #[cfg(test)]
    pub fn get_main_trace_cell(&self, col_idx: usize, step: usize) -> B {
        self.main_segment_lde.get(col_idx, step)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_segment_queries<B, H>(
    segment_lde: &Matrix<B>,
    segment_tree: &MerkleTree<H>,
    positions: &[usize],
) -> Queries
where
    B: StarkField,
    H: ElementHasher<BaseField = B>,
{
    // allocate memory for queried trace states
    let mut trace_states = Vec::with_capacity(positions.len());

    // copy values from the trace segment LDE at the specified positions into rows
    // and append the rows to trace_states
    for &i in positions.iter() {
        let row = segment_lde.columns().map(|column| column[i]).collect();
        trace_states.push(row);
    }

    // build Merkle authentication paths to the leaves specified by positions
    let trace_proof = segment_tree
        .prove_batch(positions)
        .expect("failed to generate a Merkle proof for trace queries");

    Queries::new(trace_proof, trace_states)
}
