// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::Matrix;
use air::proof::Queries;
use crypto::{ElementHasher, MerkleTree};
use math::FieldElement;
use utils::collections::Vec;

use super::TraceLde;

// TRACE COMMITMENT
// ================================================================================================

/// Execution trace commitment.
///
/// The describes one or more trace segments, each consisting of the following components:
/// * Evaluations of a trace segment's polynomials over the LDE domain.
/// * Merkle tree where each leaf in the tree corresponds to a row in the trace LDE matrix.
pub struct TraceCommitment<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    trace_lde: TraceLde<E>,
    main_segment_tree: MerkleTree<H>,
    aux_segment_trees: Vec<MerkleTree<H>>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> TraceCommitment<E, H> {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Creates a new trace commitment from the provided main trace low-degree extension and the
    /// corresponding Merkle tree commitment.
    pub fn new(
        main_trace_lde: Matrix<E::BaseField>,
        main_trace_tree: MerkleTree<H>,
        blowup: usize,
    ) -> Self {
        assert_eq!(
            main_trace_lde.num_rows(),
            main_trace_tree.leaves().len(),
            "number of rows in trace LDE must be the same as number of leaves in trace commitment"
        );
        Self {
            trace_lde: TraceLde::new(main_trace_lde, blowup),
            main_segment_tree: main_trace_tree,
            aux_segment_trees: Vec::new(),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the provided auxiliary segment trace LDE and Merkle tree to this trace commitment.
    pub fn add_segment(&mut self, aux_segment_lde: Matrix<E>, aux_segment_tree: MerkleTree<H>) {
        assert_eq!(
            aux_segment_lde.num_rows(),
            aux_segment_tree.leaves().len(),
            "number of rows in trace LDE must be the same as number of leaves in trace commitment"
        );

        self.trace_lde.add_aux_segment(aux_segment_lde);
        self.aux_segment_trees.push(aux_segment_tree);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the execution trace for this commitment.
    ///
    /// The trace contains both the main trace segment and the auxiliary trace segments (if any).
    pub fn trace_table(&self) -> &TraceLde<E> {
        &self.trace_lde
    }

    // QUERY TRACE
    // --------------------------------------------------------------------------------------------
    /// Returns trace table rows at the specified positions along with Merkle authentication paths
    /// from the commitment root to these rows.
    pub fn query(&self, positions: &[usize]) -> Vec<Queries> {
        // build queries for the main trace segment
        let mut result = vec![build_segment_queries(
            self.trace_lde.get_main_segment(),
            &self.main_segment_tree,
            positions,
        )];

        // build queries for auxiliary trace segments
        for (i, segment_tree) in self.aux_segment_trees.iter().enumerate() {
            let segment_lde = self.trace_lde.get_aux_segment(i);
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
    pub fn get_main_trace_column(&self, col_idx: usize) -> &[E::BaseField] {
        self.trace_lde.get_main_segment().get_column(col_idx)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_segment_queries<E, H>(
    segment_lde: &Matrix<E>,
    segment_tree: &MerkleTree<H>,
    positions: &[usize],
) -> Queries
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
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
