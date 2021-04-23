// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use common::{
    proof::Queries,
    utils::{evaluations_per_leaf, map_trace_to_constraint_positions},
};
use crypto::{Hasher, MerkleTree};
use math::field::FieldElement;
use std::marker::PhantomData;
use utils::{group_slice_elements, uninit_vector};

#[cfg(feature = "concurrent")]
use rayon::prelude::*;

// CONSTRAINT COMMITMENT
// ================================================================================================

pub struct ConstraintCommitment<E: FieldElement, H: Hasher> {
    evaluations: Vec<E>,
    commitment: MerkleTree,
    _element: PhantomData<E>,
    _hasher: PhantomData<H>,
}

impl<E: FieldElement, H: Hasher> ConstraintCommitment<E, H> {
    /// Commits to the constraint evaluations by putting them into a Merkle tree; since
    /// evaluations for a specific step are compressed into a single field element, we try
    /// to put multiple evaluations into a single leaf whenever possible.
    pub fn new(evaluations: Vec<E>) -> ConstraintCommitment<E, H> {
        assert!(
            evaluations.len().is_power_of_two(),
            "number of values must be a power of 2"
        );

        // determine how many evaluations should go into a single leaf and hash them
        let evaluations_per_leaf = evaluations_per_leaf::<E, H>();
        let hashed_evaluations = match evaluations_per_leaf {
            1 => hash_evaluations::<E, H, 1>(&evaluations),
            2 => hash_evaluations::<E, H, 2>(&evaluations),
            4 => hash_evaluations::<E, H, 4>(&evaluations),
            _ => panic!(
                "invalid number of evaluations per leaf: {}",
                evaluations_per_leaf
            ),
        };

        // build Merkle tree out of hashed evaluation values
        ConstraintCommitment {
            evaluations,
            commitment: MerkleTree::new(hashed_evaluations, H::hash_fn()),
            _element: PhantomData,
            _hasher: PhantomData,
        }
    }

    /// Returns the root of the commitment Merkle tree.
    pub fn root(&self) -> [u8; 32] {
        *self.commitment.root()
    }

    /// Returns the depth of the commitment Merkle tree.
    pub fn tree_depth(&self) -> usize {
        self.commitment.depth()
    }

    /// Returns constraint evaluations at the specified positions along with Merkle
    /// authentication paths from the root of the commitment to these evaluations.
    pub fn query(self, trace_positions: &[usize]) -> Queries {
        // first, map trace positions to the corresponding positions in the constraint tree;
        // we do this because multiple constraint evaluations may be stored in a single leaf
        let evaluations_per_leaf = evaluations_per_leaf::<E, H>();
        let constraint_positions =
            map_trace_to_constraint_positions(trace_positions, evaluations_per_leaf);

        // build Merkle authentication paths to the leaves specified by constraint positions
        let merkle_proof = self.commitment.prove_batch(&constraint_positions);

        // determine a set of evaluations corresponding to each position
        let mut evaluations = Vec::new();
        for position in constraint_positions {
            let start = position * evaluations_per_leaf;
            evaluations.push(self.evaluations[start..start + evaluations_per_leaf].to_vec());
        }

        Queries::new(merkle_proof, evaluations)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes hashes of evaluations grouped by N elements and returns the resulting hashes.
fn hash_evaluations<E: FieldElement, H: Hasher, const N: usize>(
    evaluations: &[E],
) -> Vec<[u8; 32]> {
    let evaluations = group_slice_elements::<E, N>(evaluations);

    let hash_fn = H::hash_fn();
    let mut result = uninit_vector::<[u8; 32]>(evaluations.len());

    #[cfg(not(feature = "concurrent"))]
    for (result, evaluations) in result.iter_mut().zip(evaluations.iter()) {
        hash_fn(E::elements_as_bytes(evaluations), result);
    }
    #[cfg(feature = "concurrent")]
    result
        .par_iter_mut()
        .zip(evaluations.par_iter())
        .for_each(|(result, evaluations)| {
            hash_fn(E::elements_as_bytes(evaluations), result);
        });

    result
}
