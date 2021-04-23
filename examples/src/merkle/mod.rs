// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::{
    utils::{bytes_to_node, node_to_bytes, rescue, TreeNode},
    Example, ExampleOptions,
};
use log::debug;
use prover::{
    self,
    crypto::MerkleTree,
    math::{
        field::{f128::BaseElement, FieldElement, StarkField},
        utils::log2,
    },
    ProofOptions, StarkProof,
};
use std::time::Instant;
use verifier::{self, VerifierError};

mod air;
use air::{build_trace, MerkleAir, PublicInputs};

#[cfg(test)]
mod tests;

// MERKLE AUTHENTICATION PATH EXAMPLE
// ================================================================================================
pub fn get_example(options: ExampleOptions, tree_depth: usize) -> Box<dyn Example> {
    Box::new(MerkleExample::new(
        tree_depth,
        options.to_proof_options(28, 64),
    ))
}

pub struct MerkleExample {
    options: ProofOptions,
    tree_root: TreeNode,
    value: TreeNode,
    index: usize,
    path: Vec<TreeNode>,
}

impl MerkleExample {
    pub fn new(tree_depth: usize, options: ProofOptions) -> MerkleExample {
        assert!(
            (tree_depth + 1).is_power_of_two(),
            "tree depth must be one less than a power of 2"
        );
        let value = (BaseElement::from(42u8), BaseElement::from(43u8));
        let index = (BaseElement::rand().as_int() % u128::pow(2, tree_depth as u32)) as usize;

        // build Merkle tree of the specified depth
        let now = Instant::now();
        let tree = build_merkle_tree(tree_depth, value, index);
        debug!(
            "Built Merkle tree of depth {} in {} ms",
            tree_depth,
            now.elapsed().as_millis(),
        );

        // compute Merkle path form the leaf specified by the index
        let now = Instant::now();
        let path = tree
            .prove(index)
            .into_iter()
            .map(bytes_to_node)
            .collect::<Vec<_>>();
        debug!(
            "Computed Merkle path from leaf {} to root {} in {} ms",
            index,
            hex::encode(tree.root()),
            now.elapsed().as_millis(),
        );

        MerkleExample {
            options,
            tree_root: bytes_to_node(*tree.root()),
            value,
            index,
            path,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl Example for MerkleExample {
    fn prove(&self) -> StarkProof {
        // generate the execution trace
        debug!(
            "Generating proof for proving membership in a Merkle tree of depth {}\n\
            ---------------------",
            self.path.len()
        );
        let now = Instant::now();
        let trace = build_trace(self.value, &self.path, self.index);
        let trace_length = trace.len();
        debug!(
            "Generated execution trace of {} registers and 2^{} steps in {} ms",
            trace.width(),
            log2(trace_length),
            now.elapsed().as_millis()
        );

        // generate the proof
        let pub_inputs = PublicInputs {
            tree_root: [self.tree_root.0, self.tree_root.1],
        };
        prover::prove::<MerkleAir>(trace, pub_inputs, self.options.clone()).unwrap()
    }

    fn verify(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            tree_root: [self.tree_root.0, self.tree_root.1],
        };
        verifier::verify::<MerkleAir>(proof, pub_inputs)
    }

    fn verify_with_wrong_inputs(&self, proof: StarkProof) -> Result<(), VerifierError> {
        let pub_inputs = PublicInputs {
            tree_root: [self.tree_root.1, self.tree_root.0],
        };
        verifier::verify::<MerkleAir>(proof, pub_inputs)
    }
}

// HELPER FUNCTIONS
// ================================================================================================
fn build_merkle_tree(depth: usize, value: TreeNode, index: usize) -> MerkleTree {
    let num_leaves = usize::pow(2, depth as u32);
    let leaf_elements = BaseElement::prng_vector([1; 32], num_leaves * 2);
    let mut leaves = Vec::new();
    for i in (0..leaf_elements.len()).step_by(2) {
        leaves.push(node_to_bytes((leaf_elements[i], leaf_elements[i + 1])));
    }

    let mut value_bytes = [0; 32];
    rescue::hash(&node_to_bytes(value), &mut value_bytes);
    leaves[index] = value_bytes;

    MerkleTree::new(leaves, rescue::hash)
}
