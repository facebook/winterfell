// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use super::RowMatrix;
use air::proof::Queries;
use alloc::vec::Vec;
use crypto::{ElementHasher, MerkleTree};
use math::FieldElement;

// CONSTRAINT COMMITMENT
// ================================================================================================

/// Constraint evaluation commitment.
///
/// The commitment consists of two components:
/// * Evaluations of composition polynomial columns over the LDE domain.
/// * Merkle tree where each leaf in the tree corresponds to a row in the composition polynomial
///   evaluation matrix.
pub struct ConstraintCommitment<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    evaluations: RowMatrix<E>,
    commitment: MerkleTree<H>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> ConstraintCommitment<E, H> {
    /// Creates a new constraint evaluation commitment from the provided composition polynomial
    /// evaluations and the corresponding Merkle tree commitment.
    pub fn new(evaluations: RowMatrix<E>, commitment: MerkleTree<H>) -> ConstraintCommitment<E, H> {
        assert_eq!(
            evaluations.num_rows(),
            commitment.leaves().len(),
            "number of rows in constraint evaluation matrix must be the same as number of leaves in constraint commitment"
        );
        ConstraintCommitment {
            evaluations,
            commitment,
        }
    }

    /// Returns the root of the commitment Merkle tree.
    pub fn root(&self) -> H::Digest {
        *self.commitment.root()
    }

    /// Returns the depth of the commitment Merkle tree.
    #[allow(unused)]
    pub fn tree_depth(&self) -> usize {
        self.commitment.depth()
    }

    /// Returns constraint evaluations at the specified positions along with Merkle authentication
    /// paths from the root of the commitment to these evaluations.
    pub fn query(self, positions: &[usize]) -> Queries {
        // build Merkle authentication paths to the leaves specified by positions
        let merkle_proof = self
            .commitment
            .prove_batch(positions)
            .expect("failed to generate a Merkle proof for constraint queries");

        // determine a set of evaluations corresponding to each position
        let mut evaluations = Vec::new();
        for &position in positions {
            let row = self.evaluations.row(position).to_vec();
            evaluations.push(row);
        }

        Queries::new(merkle_proof, evaluations)
    }
}
