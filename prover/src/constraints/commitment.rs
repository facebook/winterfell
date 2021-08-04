// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use air::proof::Queries;
use crypto::{ElementHasher, MerkleTree};
use math::FieldElement;
use utils::{batch_iter_mut, collections::Vec, uninit_vector};

#[cfg(feature = "concurrent")]
use utils::iterators::*;

// CONSTRAINT COMMITMENT
// ================================================================================================

pub struct ConstraintCommitment<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> {
    evaluations: Vec<Vec<E>>,
    commitment: MerkleTree<H>,
}

impl<E: FieldElement, H: ElementHasher<BaseField = E::BaseField>> ConstraintCommitment<E, H> {
    /// Commits to the evaluations of the constraint composition polynomial by putting it into a
    /// Merkle tree such that evaluations of all polynomial columns at the same x coordinate are
    /// placed into a single leaf.
    pub fn new(evaluations: Vec<Vec<E>>) -> ConstraintCommitment<E, H> {
        assert!(
            !evaluations.is_empty(),
            "Constraint evaluations cannot be empty"
        );
        let column_size = evaluations[0].len();
        assert!(
            column_size.is_power_of_two(),
            "evaluation column size must be a power of two"
        );
        for column in evaluations.iter() {
            assert_eq!(
                column_size,
                column.len(),
                "all evaluation columns must have the same length"
            );
        }

        // hash evaluation table into a set of digests, one per row
        let hashed_evaluations = hash_evaluations::<E, H>(&evaluations);

        // build Merkle tree out of hashed evaluation values
        let commitment = MerkleTree::new(hashed_evaluations)
            .expect("failed to construct constraint Merkle tree");
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
            let mut row = vec![E::ZERO; self.evaluations.len()];
            read_row(&self.evaluations, position, &mut row);
            evaluations.push(row);
        }

        Queries::new(merkle_proof, evaluations)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes hashes of evaluations grouped by row.
fn hash_evaluations<E, H>(evaluations: &[Vec<E>]) -> Vec<H::Digest>
where
    E: FieldElement,
    H: ElementHasher<BaseField = E::BaseField>,
{
    let mut result = unsafe { uninit_vector::<H::Digest>(evaluations[0].len()) };
    batch_iter_mut!(
        &mut result,
        128, // min batch size
        |batch: &mut [H::Digest], batch_offset: usize| {
            let mut row = vec![E::ZERO; evaluations.len()];
            for (i, result) in batch.iter_mut().enumerate() {
                read_row(evaluations, batch_offset + i, &mut row);
                *result = H::hash_elements(&row);
            }
        }
    );
    result
}

#[inline]
fn read_row<E: FieldElement>(evaluations: &[Vec<E>], i: usize, row: &mut [E]) {
    for (value, column) in row.iter_mut().zip(evaluations) {
        *value = column[i];
    }
}
